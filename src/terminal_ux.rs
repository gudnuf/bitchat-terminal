use std::collections::HashMap;
use std::str::FromStr;
use chrono::{DateTime, Local};
use cdk::nuts::Token;

fn decode_cashu_token(token_str: &str) -> Option<String> {
    // Remove the cashu: prefix if present
    let token_without_prefix = if token_str.starts_with("cashu:") {
        &token_str[6..]
    } else {
        token_str
    };
    
    // Try to decode the token
    match Token::from_str(token_without_prefix) {
        Ok(token) => {
            // Get token amount using the value() method which doesn't require keysets
            let token_amount = match token.value() {
                Ok(amount) => amount.to_string(),
                Err(_) => "unknown".to_string(),
            };
            
            // Get mint URL
            let mint_url = match token.mint_url() {
                Ok(url) => url.to_string(),
                Err(_) => "unknown mint".to_string(),
            };
            
            // Get token version info
            let version = match &token {
                Token::TokenV3(_) => "v3",
                Token::TokenV4(_) => "v4",
            };
            
            // Get memo if available
            let memo_text = match token.memo() {
                Some(memo) => format!(" ({})", memo),
                None => String::new(),
            };
            
            // Get unit
            let unit = match token.unit() {
                Some(unit) => format!("{:?}", unit).to_lowercase(),
                None => "sat".to_string(),
            };
            
            Some(format!("🎫 Cashu Token {}: {} {} from {}{}", 
                version, token_amount, unit, mint_url, memo_text))
        }
        Err(_) => None, // Not a valid cashu token
    }
}

#[derive(Debug, Clone)]
pub enum ChatMode {
    Public,
    Channel(String),
    PrivateDM { nickname: String, peer_id: String },
}

#[derive(Debug, Clone)]
pub struct ChatContext {
    pub current_mode: ChatMode,
    pub active_channels: Vec<String>,
    pub active_dms: HashMap<String, String>, // nickname -> peer_id
    pub last_private_sender: Option<(String, String)>, // (peer_id, nickname)
}

impl ChatContext {
    pub fn new() -> Self {
        Self {
            current_mode: ChatMode::Public,
            active_channels: Vec::new(),
            active_dms: HashMap::new(),
            last_private_sender: None,
        }
    }

    pub fn format_prompt(&self) -> String {
        match &self.current_mode {
            ChatMode::Public => "[Public]".to_string(),
            ChatMode::Channel(name) => format!("[{}]", name),
            ChatMode::PrivateDM { nickname, .. } => format!("[DM: {}]", nickname),
        }
    }

    pub fn get_status_line(&self) -> String {
        let mut parts = vec!["[1] Public".to_string()];
        
        // Add channels
        for (i, channel) in self.active_channels.iter().enumerate() {
            parts.push(format!("[{}] {}", i + 2, channel));
        }
        
        // Add DMs
        let dm_start = 2 + self.active_channels.len();
        for (i, (nick, _)) in self.active_dms.iter().enumerate() {
            parts.push(format!("[{}] DM:{}", i + dm_start, nick));
        }
        
        format!("Active: {}", parts.join(" "))
    }

    pub fn switch_to_number(&mut self, num: usize) -> bool {
        if num == 1 {
            self.current_mode = ChatMode::Public;
            println!("\x1b[90m─────────────────────────\x1b[0m");
            println!("\x1b[90m» Switched to Public chat. Just type to send messages.\x1b[0m");
            return true;
        }
        
        let channel_end = 1 + self.active_channels.len();
        if num > 1 && num <= channel_end {
            let channel_idx = num - 2;
            if let Some(channel) = self.active_channels.get(channel_idx) {
                self.current_mode = ChatMode::Channel(channel.clone());
                println!("\x1b[90m─────────────────────────\x1b[0m");
                println!("\x1b[90m» Switched to channel {}\x1b[0m", channel);
                return true;
            }
        }
        
        let dm_start = channel_end + 1;
        let dm_idx = num - dm_start;
        let dm_vec: Vec<_> = self.active_dms.iter().collect();
        if dm_idx < dm_vec.len() {
            let (nick, peer_id) = dm_vec[dm_idx];
            self.current_mode = ChatMode::PrivateDM {
                nickname: nick.clone(),
                peer_id: peer_id.clone(),
            };
            println!("\x1b[90m─────────────────────────\x1b[0m");
            println!("\x1b[90m» Switched to DM with {}. Just type to send messages.\x1b[0m", nick);
            return true;
        }
        
        false
    }

    pub fn add_channel(&mut self, channel: &str) {
        if !self.active_channels.contains(&channel.to_string()) {
            self.active_channels.push(channel.to_string());
        }
    }

    pub fn add_dm(&mut self, nickname: &str, peer_id: &str) {
        self.active_dms.insert(nickname.to_string(), peer_id.to_string());
    }

    pub fn enter_dm_mode(&mut self, nickname: &str, peer_id: &str) {
        self.add_dm(nickname, peer_id);
        self.current_mode = ChatMode::PrivateDM {
            nickname: nickname.to_string(),
            peer_id: peer_id.to_string(),
        };
        println!("\x1b[90m─────────────────────────\x1b[0m");
        println!("\x1b[90m» Entered DM mode with {}. Just type to send messages.\x1b[0m", nickname);
    }

    pub fn switch_to_channel(&mut self, channel: &str) {
        self.add_channel(channel);
        self.current_mode = ChatMode::Channel(channel.to_string());
        println!("\x1b[90m─────────────────────────\x1b[0m");
        println!("\x1b[90m» Switched to channel {}\x1b[0m", channel);
    }
    
    pub fn switch_to_channel_silent(&mut self, channel: &str) {
        self.add_channel(channel);
        self.current_mode = ChatMode::Channel(channel.to_string());
    }

    pub fn switch_to_public(&mut self) {
        self.current_mode = ChatMode::Public;
        println!("\x1b[90m─────────────────────────\x1b[0m");
        println!("\x1b[90m» Switched to Public chat. Just type to send messages.\x1b[0m");
    }
    
    pub fn remove_channel(&mut self, channel: &str) {
        self.active_channels.retain(|c| c != channel);
    }
    
    #[allow(dead_code)]
    pub fn get_mode_info(&self) -> String {
        match &self.current_mode {
            ChatMode::Public => "Public broadcast mode - messages visible to all".to_string(),
            ChatMode::Channel(ch) => format!("Channel {} - messages visible to channel members", ch),
            ChatMode::PrivateDM { nickname, .. } => format!("Private chat with {} - end-to-end encrypted", nickname),
        }
    }
    
    pub fn show_conversation_list(&self) {
        println!("\n╭─── Active Conversations ───╮");
        println!("│                            │");
        
        let current_indicator = |is_current: bool| if is_current { "→" } else { " " };
        
        // Public
        let is_current = matches!(&self.current_mode, ChatMode::Public);
        println!("│ {} [1] Public              │", current_indicator(is_current));
        
        // Channels
        let mut num = 2;
        for channel in &self.active_channels {
            let is_current = matches!(&self.current_mode, ChatMode::Channel(ch) if ch == channel);
            println!("│ {} [{}] {}{}│", 
                current_indicator(is_current), 
                num, 
                channel,
                " ".repeat(18 - channel.len())
            );
            num += 1;
        }
        
        // DMs
        for (nick, _) in &self.active_dms {
            let is_current = matches!(&self.current_mode, ChatMode::PrivateDM { nickname, .. } if nickname == nick);
            let dm_text = format!("DM: {}", nick);
            println!("│ {} [{}] {}{}│", 
                current_indicator(is_current), 
                num,
                dm_text,
                " ".repeat(18 - dm_text.len())
            );
            num += 1;
        }
        
        println!("│                            │");
        println!("╰────────────────────────────╯");
    }
    
    pub fn get_conversation_list_with_numbers(&self) -> String {
        let mut output = String::from("╭─── Select Conversation ───╮\n");
        
        // Public
        output.push_str("│  1. Public                │\n");
        
        // Channels
        let mut num = 2;
        for channel in &self.active_channels {
            output.push_str(&format!("│  {}. {}{}│\n", 
                num, 
                channel,
                " ".repeat(20 - channel.len())
            ));
            num += 1;
        }
        
        // DMs
        for (nick, _) in &self.active_dms {
            let dm_text = format!("DM: {}", nick);
            output.push_str(&format!("│  {}. {}{}│\n", 
                num,
                dm_text,
                " ".repeat(20 - dm_text.len())
            ));
            num += 1;
        }
        
        output.push_str("╰───────────────────────────╯");
        output
    }
}

pub fn format_message_display(
    timestamp: DateTime<Local>,
    sender: &str,
    content: &str,
    is_private: bool,
    is_channel: bool,
    channel_name: Option<&str>,
    recipient: Option<&str>,
    my_nickname: &str,
) -> String {
    let time_str = timestamp.format("%H:%M").to_string();
    
    // Check if the content is a cashu token and decode it if so
    let display_content = if content.starts_with("cashu:") || content.starts_with("cashu") {
        if let Some(decoded) = decode_cashu_token(content) {
            decoded
        } else {
            content.to_string()
        }
    } else {
        content.to_string()
    };
    
    if is_private {
        // Use orange for private messages (matching iOS)
        if sender == my_nickname {
            // Message I sent - use brighter orange
            if let Some(recipient) = recipient {
                format!("\x1b[2;38;5;208m[{}|DM]\x1b[0m \x1b[38;5;214m<you → {}>\x1b[0m {}", time_str, recipient, display_content)
            } else {
                format!("\x1b[2;38;5;208m[{}|DM]\x1b[0m \x1b[38;5;214m<you → ???>\x1b[0m {}", time_str, display_content)
            }
        } else {
            // Message I received - use normal orange
            format!("\x1b[2;38;5;208m[{}|DM]\x1b[0m \x1b[38;5;208m<{} → you>\x1b[0m {}", time_str, sender, display_content)
        }
    } else if is_channel {
        // Use blue for channel messages (matching iOS)
        if sender == my_nickname {
            // My messages - use light blue (256-color)
            if let Some(channel) = channel_name {
                format!("\x1b[2;34m[{}|{}]\x1b[0m \x1b[38;5;117m<{} @ {}>\x1b[0m {}", time_str, channel, sender, channel, display_content)
            } else {
                format!("\x1b[2;34m[{}|Ch]\x1b[0m \x1b[38;5;117m<{} @ ???>\x1b[0m {}", time_str, sender, display_content)
            }
        } else {
            // Other users - use normal blue
            if let Some(channel) = channel_name {
                format!("\x1b[2;34m[{}|{}]\x1b[0m \x1b[34m<{} @ {}>\x1b[0m {}", time_str, channel, sender, channel, display_content)
            } else {
                format!("\x1b[2;34m[{}|Ch]\x1b[0m \x1b[34m<{} @ ???>\x1b[0m {}", time_str, sender, display_content)
            }
        }
    } else {
        // Public message - use green for metadata
        if sender == my_nickname {
            // My messages - use light green (256-color)
            format!("\x1b[2;32m[{}]\x1b[0m \x1b[38;5;120m<{}>\x1b[0m {}", time_str, sender, display_content)
        } else {
            // Other users - use normal green
            format!("\x1b[2;32m[{}]\x1b[0m \x1b[32m<{}>\x1b[0m {}", time_str, sender, content)
        }
    }
}

pub fn print_help() {
    println!("\n\x1b[38;5;46m━━━ BitChat Commands ━━━\x1b[0m\n");
    
    // General
    println!("\x1b[38;5;40m▶ General\x1b[0m");
    println!("  \x1b[36m/help\x1b[0m         Show this help menu");
    println!("  \x1b[36m/name\x1b[0m \x1b[90m<name>\x1b[0m  Change your nickname");
    println!("  \x1b[36m/status\x1b[0m       Show connection info");
    println!("  \x1b[36m/clear\x1b[0m        Clear the screen");
    println!("  \x1b[36m/exit\x1b[0m         Quit BitChat\n");
    
    // Navigation
    println!("\x1b[38;5;40m▶ Navigation\x1b[0m");
    println!("  \x1b[36m1-9\x1b[0m           Quick switch to conversation");
    println!("  \x1b[36m/list\x1b[0m         Show all conversations");
    println!("  \x1b[36m/switch\x1b[0m       Interactive conversation switcher");
    println!("  \x1b[36m/public\x1b[0m       Go to public chat\n");
    
    // Messaging
    println!("\x1b[38;5;40m▶ Messaging\x1b[0m");
    println!("  \x1b[90m(type normally to send in current mode)\x1b[0m");
    println!("  \x1b[36m/dm\x1b[0m \x1b[90m<name>\x1b[0m    Start private conversation");
    println!("  \x1b[36m/dm\x1b[0m \x1b[90m<name> <msg>\x1b[0m Send quick private message");
    println!("  \x1b[36m/reply\x1b[0m        Reply to last private message\n");
    
    // Channels
    println!("\x1b[38;5;40m▶ Channels\x1b[0m");
    println!("  \x1b[36m/j\x1b[0m \x1b[90m#channel\x1b[0m   Join or create a channel");
    println!("  \x1b[36m/j\x1b[0m \x1b[90m#channel <password>\x1b[0m Join with password");
    println!("  \x1b[36m/leave\x1b[0m        Leave current channel");
    println!("  \x1b[36m/pass\x1b[0m \x1b[90m<pwd>\x1b[0m   Set channel password (owner only)");
    println!("  \x1b[36m/transfer\x1b[0m \x1b[90m@user\x1b[0m Transfer ownership (owner only)\n");
    
    // Discovery
    println!("\x1b[38;5;40m▶ Discovery\x1b[0m");
    println!("  \x1b[36m/channels\x1b[0m     List all discovered channels");
    println!("  \x1b[36m/online\x1b[0m       Show who's online");
    println!("  \x1b[36m/w\x1b[0m            Alias for /online");
    println!("  \x1b[36m/peers\x1b[0m        Show peer encryption status");
    println!("  \x1b[36m/peers\x1b[0m \x1b[90mencryption\x1b[0m Detailed encryption status\n");
    
    // Privacy & Security
    println!("\x1b[38;5;40m▶ Privacy & Security\x1b[0m");
    println!("  \x1b[36m/encryption\x1b[0m   Detailed encryption status");
    println!("  \x1b[36m/block\x1b[0m \x1b[90m@user\x1b[0m  Block a user");
    println!("  \x1b[36m/block\x1b[0m        List blocked users");
    println!("  \x1b[36m/unblock\x1b[0m \x1b[90m@user\x1b[0m Unblock a user\n");
    
    // Payments
    println!("\x1b[38;5;40m▶ Payments\x1b[0m");
    println!("  \x1b[36m/pay\x1b[0m \x1b[90m@user <amount>\x1b[0m Send Cashu payment via DM");
    println!("  \x1b[36m/cashu_send\x1b[0m \x1b[90m<amount>\x1b[0m Send Cashu token to current chat");
    println!("  \x1b[36m/cashu\x1b[0m \x1b[90m<command>\x1b[0m  Manage Cashu wallet\n");
    
    println!("\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
}

#[allow(dead_code)]
pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

// Helper to extract message target from chat mode
impl ChatMode {
    pub fn get_channel(&self) -> Option<&str> {
        match self {
            ChatMode::Channel(name) => Some(name),
            _ => None,
        }
    }
    
    #[allow(dead_code)]
    pub fn get_dm_target(&self) -> Option<(&str, &str)> {
        match self {
            ChatMode::PrivateDM { nickname, peer_id } => Some((nickname, peer_id)),
            _ => None,
        }
    }
    
    #[allow(dead_code)]
    pub fn is_private(&self) -> bool {
        matches!(self, ChatMode::PrivateDM { .. })
    }
} 