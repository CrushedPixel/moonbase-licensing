use anyhow::{Context, Result};
use console::style;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use moonbase_licensing::{ActivationState, LicenseActivationConfig, LicenseActivator};
use std::env;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// This CLI demonstrates the usage of the moonbase-licensing library by providing
/// both online and offline activation workflows.
///
/// Configuration can be provided via environment variables or interactive prompts.
/// Generated machine.dt files can be used for offline activation through the
/// Moonbase dashboard.
fn main() -> Result<()> {
    println!("{}", style("moonbase-licensing Test CLI").cyan().bold());
    println!("{}", style("─".repeat(30)).dim());

    let config = get_configuration()?;
    print_configuration(&config);

    let mut activator = LicenseActivator::spawn(config.clone());

    // check initial license activation status (cached file)

    match activator.state_recv.recv() {
        Ok(ActivationState::Activated(claims)) => {
            println!("{} License is active", style("✓").green().bold());
            print_license_details(&claims);
        }
        Ok(ActivationState::NeedsActivation(_)) | Err(_) => {
            println!("{} No active license found\n", style("⚠").yellow());
            run_activation(&mut activator)?;
        }
    }

    Ok(())
}

/// Runs the activation process
fn run_activation(activator: &mut LicenseActivator) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan} {msg}")?);
    spinner.set_message("Starting activation...");

    let mut activation_url: Option<String> = None;
    let mut user_chose_method = false;

    loop {
        match activator.state_recv.try_recv() {
            Ok(ActivationState::Activated(claims)) => {
                spinner.finish_and_clear();
                println!(
                    "\n{} License activated successfully!",
                    style("✓").green().bold()
                );
                print_license_details(&claims);
                break;
            }
            Ok(ActivationState::NeedsActivation(Some(url))) => {
                if !user_chose_method && activation_url.as_ref() != Some(&url) {
                    activation_url = Some(url.clone());
                    spinner.finish_and_clear();
                    user_chose_method = true;
                    handle_activation_options(&url, activator)?;

                    // Restart spinner after user interaction
                    spinner.set_message("Waiting for activation...");
                    spinner.enable_steady_tick(Duration::from_millis(100));
                }
            }
            Ok(ActivationState::NeedsActivation(None)) => {
                spinner.set_message("Requesting activation URL...");
            }
            Err(_) => {
                // No update yet
            }
        }

        // Check for errors
        while let Ok(error) = activator.error_recv.try_recv() {
            spinner.finish_and_clear();
            println!("{} {error}", style("Error:").red().bold());

            // Restart spinner after error display
            spinner.enable_steady_tick(Duration::from_millis(100));
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    spinner.finish_and_clear();
    Ok(())
}

/// Handles activation method selection
fn handle_activation_options(url: &str, activator: &mut LicenseActivator) -> Result<()> {
    println!(
        "\n{} {}\n",
        style("Activation URL:").dim(),
        style(url).cyan().underlined()
    );

    let choices = vec![
        "🌐 Online activation (open browser)",
        "🔑 Offline activation (enter token)",
        "⏳ Wait for another instance",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose activation method")
        .items(&choices)
        .default(0)
        .interact()?;

    match selection {
        0 => {
            println!("{} Opening browser...", style("→").cyan());
            activator
                .poll_online_activation
                .store(true, Ordering::Relaxed);

            if let Err(e) = open::that(url) {
                println!("{} Could not open browser: {}", style("⚠").yellow(), e);
                println!("  Please manually open the URL above");
            } else {
                println!("  Complete activation in your browser, then return here");
            }
        }
        1 => {
            // Get path for machine file first
            println!("\n{}", style("Preparing offline activation...").dim());

            let path: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Where to save machine file")
                .default("machine.dt".to_string())
                .show_default(true)
                .interact_text()?;

            // Generate and save machine file
            let machine_file = activator.machine_file_contents();
            std::fs::write(&path, &machine_file)?;
            println!(
                "{} Saved machine file to {}",
                style("✓").green(),
                style(&path).yellow()
            );

            println!("\n{}", style("Offline Activation Steps:").bold());
            println!(
                "  1. Upload {} to your Moonbase dashboard",
                style(&path).yellow()
            );
            println!("  2. Generate an offline activation token");
            println!("  3. Paste the token below\n");

            let token: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Offline token")
                .interact_text()?;

            if !token.trim().is_empty() {
                let spinner = ProgressBar::new_spinner();
                spinner.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.cyan} Validating token...")
                        .unwrap(),
                );
                spinner.enable_steady_tick(Duration::from_millis(100));

                activator.submit_offline_activation_token(token.trim());

                std::thread::sleep(Duration::from_millis(500));
                spinner.finish_and_clear();
            }
        }
        2 => {
            println!(
                "{} Waiting for activation from another instance...",
                style("⏳").cyan()
            );
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Prints license details.
fn print_license_details(claims: &moonbase_licensing::LicenseTokenClaims) {
    println!();
    println!(
        "  {} {}",
        style("Licensed to:").dim(),
        style(&claims.user_name).green()
    );
    println!("  {} {}", style("Device:").dim(), claims.device_signature);
    println!(
        "  {} {}",
        style("Trial:").dim(),
        if claims.trial {
            style("Yes").yellow()
        } else {
            style("No").green()
        }
    );

    if let Some(expires) = claims.expires_at {
        println!("  {} {}", style("Expires:").dim(), expires);
    }
    println!();
}

fn print_configuration(config: &LicenseActivationConfig) {
    println!("\n{}", style("Configuration").underlined());
    println!("  {} {}", style("Vendor:").dim(), config.vendor_id);
    println!("  {} {}", style("Product:").dim(), config.product_id);
    println!("  {} {}", style("Device:").dim(), config.device_name);
    println!(
        "  {} {}\n",
        style("Cache:").dim(),
        config.cached_token_path.display()
    );
}

/// Gets configuration from environment or prompts the user.
fn get_configuration() -> Result<LicenseActivationConfig> {
    let vendor_id = get_env_or_prompt("MOONBASE_VENDOR_ID", "Vendor ID")?;
    let product_id = get_env_or_prompt("MOONBASE_PRODUCT_ID", "Product ID")?;
    let jwt_pubkey = get_jwt_public_key()?;

    let device_name = env::var("DEVICE_NAME").unwrap_or_else(|_| {
        format!(
            "Example-{}",
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "Device".to_string())
        )
    });

    let device_signature = env::var("DEVICE_SIGNATURE").unwrap_or_else(|_| 
            // this is a sensible crate to obtain the device signature
            // if you don't want to invalidate a license when part of the hardware is changed,
            // in which case you can look into something like MachineID.
            hardware_id::get_id().unwrap());

    let cached_token_path = env::var("LICENSE_CACHE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::temp_dir().join("moonbase_example.jwt"));

    Ok(LicenseActivationConfig {
        vendor_id,
        product_id,
        jwt_pubkey,
        device_signature,
        device_name,
        cached_token_path,
        online_token_refresh_threshold: Duration::from_secs(24 * 3600),
        online_token_expiration_threshold: Duration::from_secs(3600),
    })
}

/// Gets environment variable or prompts for input
fn get_env_or_prompt(env_var: &str, prompt: &str) -> Result<String> {
    env::var(env_var)
        .or_else(|_| {
            Input::with_theme(&ColorfulTheme::default())
                .with_prompt(prompt)
                .interact_text()
                .map_err(|e| env::VarError::NotUnicode(e.to_string().into()))
        })
        .context(format!("{prompt} is required"))
}

/// Retrieves JWT public key from environment or user input.
fn get_jwt_public_key() -> Result<String> {
    env::var("MOONBASE_JWT_PUBKEY")
        .or_else(|_| {
            println!("{}", style("JWT Public Key Required").yellow());
            println!("Paste the PEM key below, ending with '-----END RSA PUBLIC KEY-----':");
            println!();

            let mut key = String::new();
            let mut line = String::new();

            loop {
                std::io::stdin().read_line(&mut line).unwrap();
                key.push_str(&line);

                if line.trim() == "-----END RSA PUBLIC KEY-----" {
                    break;
                }
                line.clear();
            }

            if key.trim().is_empty() {
                Err(env::VarError::NotPresent)
            } else {
                Ok(key)
            }
        })
        .context("JWT public key is required")
}
