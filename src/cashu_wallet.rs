use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use bip39::rand::{thread_rng, Rng};
use bip39::Mnemonic;
use cdk::cdk_database;
use cdk::cdk_database::WalletDatabase;
use cdk::nuts::CurrencyUnit;
use cdk::wallet::{HttpClient, MultiMintWallet, Wallet, WalletBuilder, SendOptions};
use cdk::wallet::MintConnector;
use cdk::wallet::types::{WalletKey, SendKind};
use cdk::mint_url::MintUrl;
use cdk::Amount;
use cdk::amount::SplitTarget;
use cdk::nuts::{MintQuoteState, NotificationPayload};
use cdk::wallet::WalletSubscription;
use cdk_sqlite::WalletSqliteDatabase;
use cdk::nuts::Token;

const DEFAULT_CASHU_DIR: &str = ".bitchat-cashu";

pub struct CashuWallet {
    multi_mint_wallet: MultiMintWallet,
    work_dir: PathBuf,
}

impl CashuWallet {
    pub async fn new() -> Result<Self> {
        let work_dir = match home::home_dir() {
            Some(home_dir) => home_dir.join(DEFAULT_CASHU_DIR),
            None => PathBuf::from(DEFAULT_CASHU_DIR),
        };

        fs::create_dir_all(&work_dir)?;

        let localstore: Arc<dyn WalletDatabase<Err = cdk_database::Error> + Send + Sync> = {
            let sql_path = work_dir.join("cashu-wallet.sqlite");
            Arc::new(WalletSqliteDatabase::new(&sql_path).await?)
        };

        let seed_path = work_dir.join("seed");
        let mnemonic = match fs::metadata(seed_path.clone()) {
            Ok(_) => {
                let contents = fs::read_to_string(seed_path.clone())?;
                Mnemonic::from_str(&contents)?
            }
            Err(_) => {
                let mut rng = thread_rng();
                let random_bytes: [u8; 32] = rng.gen();
                let mnemonic = Mnemonic::from_entropy(&random_bytes)?;
                fs::write(seed_path, mnemonic.to_string())?;
                mnemonic
            }
        };

        let seed = mnemonic.to_seed_normalized("");
        let mut wallets: Vec<Wallet> = Vec::new();
        let mints = localstore.get_mints().await?;

        for (mint_url, mint_info) in mints {
            let units = if let Some(mint_info) = mint_info {
                mint_info.supported_units().into_iter().cloned().collect()
            } else {
                vec![CurrencyUnit::Sat]
            };

            for unit in units {
                let wallet = WalletBuilder::new()
                    .mint_url(mint_url.clone())
                    .unit(unit)
                    .localstore(localstore.clone())
                    .seed(&seed)
                    .build()?;

                let wallet_clone = wallet.clone();
                tokio::spawn(async move {
                    if let Err(err) = wallet_clone.get_mint_info().await {
                        eprintln!("Could not get mint info for {}: {}", wallet_clone.mint_url, err);
                    }
                });

                wallets.push(wallet);
            }
        }

        let multi_mint_wallet = MultiMintWallet::new(localstore, Arc::new(seed), wallets);

        Ok(Self {
            multi_mint_wallet,
            work_dir,
        })
    }

    pub async fn handle_command<F>(&self, command: &str, send_message_fn: F) -> Result<()> 
    where
        F: Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send>> + Send + Sync,
    {
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        
        // Handle empty command or help
        if parts.is_empty() || command.trim().is_empty() {
            self.print_help();
            return Ok(());
        }

        match parts[0] {
            "balance" => self.balance().await,
            "mint_info" => {
                let mint_url = parts.get(1).map(|s| s.to_string());
                self.mint_info(mint_url).await
            }
            "mint" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet mint <amount> [mint_url] [unit]");
                    return Ok(());
                }
                let amount = parts[1].parse::<u64>().map_err(|_| anyhow::anyhow!("Invalid amount"))?;
                let mint_url = parts.get(2).map(|s| s.to_string());
                let unit = parts.get(3).unwrap_or(&"sat").to_string();
                self.mint(amount, mint_url, &unit).await
            }
            "send_to_chat" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet send_to_chat <amount> [mint_url] [unit]");
                    return Ok(());
                }
                let amount = parts[1].parse::<u64>().map_err(|_| anyhow::anyhow!("Invalid amount"))?;
                let mint_url = parts.get(2).map(|s| s.to_string());
                let unit = parts.get(3).unwrap_or(&"sat").to_string();
                
                // Create token and send it to chat
                match self.send(amount, mint_url, &unit).await {
                    Ok(token) => {
                        let cashu_message = format!("cashu:{}", token);
                        
                        // Send the cashu message using the provided function
                        match send_message_fn(&cashu_message).await {
                            Ok(_) => {
                                println!("✅ Cashu token sent to chat!");
                            }
                            Err(e) => {
                                println!("\x1b[91m❌ Failed to send message: {}\x1b[0m", e);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        println!("\x1b[91m❌ Failed to create cashu token: {}\x1b[0m", e);
                        Err(e)
                    }
                }
            }
            "delete_mint" => {
                if parts.len() < 2 {
                    println!("Usage: /wallet delete_mint <mint_url>");
                    return Ok(());
                }
                let mint_url = parts[1].to_string();
                self.delete_mint(&mint_url).await
            }
            "help" => {
                self.print_help();
                Ok(())
            }
            _ => {
                println!("Unknown command: {}", parts[0]);
                Ok(())
            }
        }
    }
    async fn get_available_wallet(&self, unit: CurrencyUnit) -> Result<Wallet> {
        let balances = self.multi_mint_wallet.get_balances(&unit).await?;
        
        // Find the wallet with the highest balance
        let mut best_wallet: Option<(MintUrl, Amount)> = None;
        
        for (mint_url, balance) in balances.iter() {
            if balance > &Amount::ZERO {
                match &best_wallet {
                    None => best_wallet = Some((mint_url.clone(), *balance)),
                    Some((_, current_best_balance)) => {
                        if balance > current_best_balance {
                            best_wallet = Some((mint_url.clone(), *balance));
                        }
                    }
                }
            }
        }
        
        // If we found a wallet with balance, return it
        if let Some((mint_url, _)) = best_wallet {
            let wallet_key = WalletKey::new(mint_url, unit.clone());
            if let Some(wallet) = self.multi_mint_wallet.get_wallet(&wallet_key).await {
                return Ok(wallet.clone());
            }
        }
        
        // If no wallet with balance found, try to get any wallet for this unit
        let mints = self.multi_mint_wallet.localstore.get_mints().await?;
        for (mint_url, _) in mints {
            let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
            if let Some(wallet) = self.multi_mint_wallet.get_wallet(&wallet_key).await {
                return Ok(wallet.clone());
            }
        }
        
        Err(anyhow::anyhow!("No wallets available for unit {}", unit))
    }

    async fn balance(&self) -> Result<()> {
        let unit = CurrencyUnit::Sat;
        
        match self.multi_mint_wallet.get_balances(&unit).await {
            Ok(wallets) => {
                let mut total_balance = Amount::ZERO;
                let mut mint_count = 0;
                
                println!("💰 Wallet Balances:");
                
                for (mint_url, amount) in wallets.iter() {
                    if amount > &Amount::ZERO {
                        println!("  📍 {}: {} {}", mint_url, amount, unit);
                        total_balance += *amount;
                        mint_count += 1;
                    }
                }
                
                if mint_count == 0 {
                    println!("  No funds in any mint");
                } else {
                    println!("💰 Total Balance: {} {}", total_balance, unit);
                }
            }
            Err(e) => eprintln!("Error getting balances: {}", e),
        }
        Ok(())
    }

    async fn mint_info(&self, mint_url: Option<String>) -> Result<()> {
        let mint_url = if let Some(url) = mint_url {
            MintUrl::from_str(&url)?
        } else {
            // Get any available wallet and use its mint URL
            let wallet = self.get_available_wallet(CurrencyUnit::Sat).await?;
            wallet.mint_url.clone()
        };
        
        let client = HttpClient::new(mint_url.clone(), None);

        match client.get_mint_info().await {
            Ok(info) => {
                println!("🏦 Mint Info for: {}", mint_url);
                println!("{:#?}", info);
            }
            Err(e) => eprintln!("Error getting mint info for {}: {}", mint_url, e),
        }
        Ok(())
    }

    async fn get_or_create_wallet(&self, mint_url: &MintUrl, unit: CurrencyUnit) -> Result<Wallet> {
        // Check if wallet already exists using the proper WalletKey
        let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
        
        match self.multi_mint_wallet.get_wallet(&wallet_key).await {
            Some(wallet) => Ok(wallet.clone()),
            None => {
                // Create new wallet using MultiMintWallet's method which properly adds it to localstore
                self.multi_mint_wallet
                    .create_and_add_wallet(&mint_url.to_string(), unit, None)
                    .await
            }
        }
    }

    async fn mint(&self, amount: u64, mint_url: Option<String>, unit: &str) -> Result<()> {
        let unit = CurrencyUnit::from_str(unit)?;
        let amount = Amount::from(amount);

        let wallet = if let Some(url) = mint_url {
            let mint_url = MintUrl::from_str(&url)?;
            self.get_or_create_wallet(&mint_url, unit.clone()).await?
        } else {
            self.get_available_wallet(unit.clone()).await?
        };

        // Create mint quote
        let quote = wallet.mint_quote(amount, None).await?;

        println!("🏦 Mint quote created:");
        println!("Quote ID: {}", quote.id);
        println!("Amount: {} {}", amount, unit);
        println!("Payment request: {}", quote.request);
        println!("Please pay this invoice to mint tokens");

        // Subscribe to quote state changes
        let mut subscription = wallet
            .subscribe(WalletSubscription::Bolt11MintQuoteState(vec![quote.id.clone()]))
            .await;

        println!("⏳ Waiting for payment...");

        // Wait for payment
        while let Some(msg) = subscription.recv().await {
            if let NotificationPayload::MintQuoteBolt11Response(response) = msg {
                if response.state == MintQuoteState::Paid {
                    println!("✅ Payment received!");
                    break;
                }
            }
        }

        // Mint the tokens
        let proofs = wallet.mint(&quote.id, SplitTarget::default(), None).await?;
        let receive_amount = proofs.iter().fold(Amount::ZERO, |acc, p| acc + p.amount);

        println!("🎉 Successfully minted {} {} from {}", receive_amount, unit, wallet.mint_url);

        Ok(())
    }

    pub async fn send(&self, amount: u64, mint_url: Option<String>, unit: &str) -> Result<Token> {
        let unit = CurrencyUnit::from_str(unit)?;
        let amount = Amount::from(amount);

        // If mint_url is provided, use that specific mint, otherwise find the first mint with sufficient balance
        let wallet = if let Some(url) = mint_url {
            let mint_url = MintUrl::from_str(&url)?;
            self.get_or_create_wallet(&mint_url, unit.clone()).await?
        } else {
            // Find a wallet with sufficient balance
            let balances = self.multi_mint_wallet.get_balances(&unit).await?;
            let mut selected_mint_url = None;
            
            for (mint_url, balance) in balances.iter() {
                if balance >= &amount {
                    selected_mint_url = Some(mint_url.clone());
                    break;
                }
            }
            
            let mint_url = selected_mint_url.ok_or_else(|| {
                anyhow::anyhow!("No mint found with sufficient balance of {} {}", amount, unit)
            })?;
            
            self.get_or_create_wallet(&mint_url, unit.clone()).await?
        };

        // Check if wallet has sufficient balance
        let balances = self.multi_mint_wallet.get_balances(&unit).await?;
        let balance = balances.get(&wallet.mint_url).unwrap_or(&Amount::ZERO);
        
        if balance < &amount {
            return Err(anyhow::anyhow!(
                "Insufficient balance. Available: {} {}, Requested: {} {}",
                balance, unit, amount, unit
            ));
        }

        // Prepare the send with default options
        let send_options = SendOptions {
            memo: None,
            send_kind: SendKind::OnlineExact,
            include_fee: false,
            conditions: None,
            ..Default::default()
        };

        // Create the token using the new API
        let prepared_send = wallet.prepare_send(amount, send_options).await?;
        let token = wallet.send(prepared_send, None).await?;

        println!("📤 Token created successfully!");
        println!("Amount: {} {}", amount, unit);
        println!("Mint: {}", wallet.mint_url);
        
        Ok(token)
    }

    async fn delete_mint(&self, mint_url: &str) -> Result<()> {
        let mint_url = MintUrl::from_str(mint_url)?;
        
        // Check all possible currency units for this mint
        let all_units = vec![
            CurrencyUnit::Sat,
            CurrencyUnit::Msat,
            CurrencyUnit::Usd,
            CurrencyUnit::Eur,
            CurrencyUnit::Auth,
        ];
        
        let mut found_wallets = Vec::new();
        let mut total_balance = Amount::ZERO;
        
        // Check each unit for this mint
        for unit in all_units {
            let balances = self.multi_mint_wallet.get_balances(&unit).await?;
            if let Some(balance) = balances.get(&mint_url) {
                if balance > &Amount::ZERO {
                    found_wallets.push((unit.clone(), *balance));
                    total_balance += *balance;
                }
            } else {
                // Check if wallet exists even with zero balance
                let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
                if let Some(_) = self.multi_mint_wallet.get_wallet(&wallet_key).await {
                    found_wallets.push((unit.clone(), Amount::ZERO));
                }
            }
        }
        
        if found_wallets.is_empty() {
            println!("❌ No wallets found for mint: {}", mint_url);
            return Ok(());
        }
        
        // Show what will be deleted
        println!("\n⚠️  \x1b[91mWARNING: You are about to PERMANENTLY DELETE mint: {}\x1b[0m", mint_url);
        println!("This will remove the following wallets and their balances:");
        
        for (unit, balance) in &found_wallets {
            if balance > &Amount::ZERO {
                println!("  🔥 \x1b[91m{} {}\x1b[0m - \x1b[93mFUNDS WILL BE LOST!\x1b[0m", balance, unit);
            } else {
                println!("  📦 {} {} (empty wallet)", balance, unit);
            }
        }
        
        if total_balance > Amount::ZERO {
            println!("\n\x1b[91m💀 TOTAL FUNDS THAT WILL BE LOST: {} sats equivalent\x1b[0m", total_balance);
        }
        
        println!("\n🔥 \x1b[91mProceeding with deletion...\x1b[0m");
        
        // Delete all wallets for this mint
        let mut deleted_count = 0;
        for (unit, _) in found_wallets {
            let wallet_key = WalletKey::new(mint_url.clone(), unit.clone());
            self.multi_mint_wallet.remove_wallet(&wallet_key).await;
            deleted_count += 1;
        }
        
        // Remove the mint from the database
        if let Err(e) = self.multi_mint_wallet.localstore.remove_mint(mint_url.clone()).await {
            println!("⚠️  Warning: Failed to remove mint from database: {}", e);
        }
        
        println!("✅ Successfully deleted {} wallet(s) for mint: {}", deleted_count, mint_url);
        
        Ok(())
    }

    pub fn print_help(&self) {
        println!("\n\x1b[38;5;46m━━━ Cashu Wallet Commands ━━━\x1b[0m\n");
        
        println!("\x1b[38;5;40m▶ Balance & Info\x1b[0m");
        println!("  \x1b[36m/wallet balance\x1b[0m         Show wallet balance");
        println!("  \x1b[36m/wallet mint_info\x1b[0m \x1b[90m[mint_url]\x1b[0m Get mint information");
        println!("  \x1b[36m/wallet decode\x1b[0m \x1b[90m<token>\x1b[0m   Decode a cashu token");
        println!("  \x1b[36m/wallet pending\x1b[0m        Check pending operations\n");
        
        println!("\x1b[38;5;40m▶ Send & Receive\x1b[0m");
        println!("  \x1b[36m/wallet send\x1b[0m \x1b[90m<amount> [mint_url] [unit]\x1b[0m Create a token (display only)");
        println!("  \x1b[36m/wallet send_to_chat\x1b[0m \x1b[90m<amount> [mint_url] [unit]\x1b[0m Create token and send to chat");
        println!("  \x1b[36m/cashu_send\x1b[0m \x1b[90m<amount> [mint_url] [unit]\x1b[0m Create token and send to chat (shortcut)");
        println!("  \x1b[36m/wallet receive\x1b[0m \x1b[90m<token>\x1b[0m   Receive a cashu token");
        println!("  \x1b[36m/wallet mint\x1b[0m \x1b[90m<amount> [mint_url] [unit]\x1b[0m Mint tokens from lightning");
        println!("  \x1b[36m/wallet melt\x1b[0m \x1b[90m<invoice>\x1b[0m   Pay lightning invoice\n");
        
        println!("\x1b[38;5;40m▶ Wallet Management\x1b[0m");
        println!("  \x1b[36m/wallet restore\x1b[0m \x1b[90m[mint_url]\x1b[0m Restore wallet from mint");
        println!("  \x1b[36m/wallet burn\x1b[0m \x1b[90m[mint_url]\x1b[0m    Burn spent tokens");
        println!("  \x1b[36m/wallet delete_mint\x1b[0m \x1b[90m<mint_url>\x1b[0m \x1b[91mPERMANENTLY DELETE mint & lose funds\x1b[0m");
        println!("  \x1b[36m/wallet help\x1b[0m           Show this help\n");
        
        println!("\x1b[90mExample: /wallet send 1000\x1b[0m");
        println!("\x1b[90mExample: /wallet send 1000 https://mint.example.com sat\x1b[0m");
        println!("\x1b[90mExample: /wallet mint 1000 https://mint.example.com sat\x1b[0m");
        println!("\x1b[90mExample: /cashu_send 1000 (shortcut to send to chat)\x1b[0m");
        println!("\x1b[90mExample: /wallet receive cashuAeyJ0eXAiOiJQMlBLI...\x1b[0m");
        println!("\x1b[90mExample: /wallet delete_mint https://mint.example.com\x1b[0m");
    }
} 