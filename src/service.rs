use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub geosite: String,
    #[serde(default)]
    pub geoip: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceList {
    pub services: Vec<Service>,
}

impl ServiceList {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&self.services)?)?;
        Ok(())
    }

    pub fn enabled_services(&self) -> impl Iterator<Item = &Service> {
        self.services.iter().filter(|s| s.enabled)
    }

    pub fn find(&self, id: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.id == id)
    }

    pub fn find_mut(&mut self, id: &str) -> Option<&mut Service> {
        self.services.iter_mut().find(|s| s.id == id)
    }
}

pub fn builtin_services() -> Vec<Service> {
    vec![
        svc("netflix", "Netflix", "netflix", &[
            "netflix.com", "*.netflix.com", "nflxvideo.net", "*.nflxvideo.net",
            "nflximg.net", "*.nflximg.net", "nflxext.com", "*.nflxext.com",
            "nflxso.net", "*.nflxso.net", "netflix.net", "*.netflix.net",
        ], &[
            "23.246.0.0/18", "37.77.184.0/21", "38.72.126.0/23",
            "45.57.0.0/17", "64.120.128.0/17", "66.197.128.0/17",
            "108.175.32.0/20", "185.2.220.0/22", "185.9.188.0/22",
            "192.173.64.0/18", "198.38.96.0/19", "198.45.48.0/20",
            "208.75.76.0/22",
        ], "netflix", ""),

        svc("disney", "Disney+", "disney", &[
            "disney.com", "*.disney.com", "disneyplus.com", "*.disneyplus.com",
            "dssott.com", "*.dssott.com", "bamgrid.com", "*.bamgrid.com",
            "disney-plus.net", "*.disney-plus.net", "disneystreaming.com", "*.disneystreaming.com",
            "disney.io", "*.disney.io", "starott.com", "*.starott.com",
        ], &[], "disney", ""),

        svc("hbo", "HBO MAX", "hbo", &[
            "hbo.com", "*.hbo.com", "hbomax.com", "*.hbomax.com",
            "max.com", "*.max.com", "hbonow.com", "*.hbonow.com",
            "hbogo.com", "*.hbogo.com",
        ], &[], "hbo", ""),

        svc("appletv", "Apple TV+", "appletv", &[
            "tv.apple.com", "play.itunes.apple.com",
            "play-edge.itunes.apple.com", "*.apple.com",
        ], &[
            "17.0.0.0/8",
        ], "", ""),

        svc("primevideo", "Prime Video", "primevideo", &[
            "primevideo.com", "*.primevideo.com",
            "amazon.com", "*.amazon.com",
            "amazonvideo.com", "*.amazonvideo.com",
            "media-amazon.com", "*.media-amazon.com",
            "aiv-cdn.net", "*.aiv-cdn.net",
        ], &[], "primevideo", ""),

        svc("youtube", "YouTube", "youtube", &[
            "youtube.com", "*.youtube.com",
            "googlevideo.com", "*.googlevideo.com",
            "ytimg.com", "*.ytimg.com",
            "youtu.be", "yt.be",
            "youtube-nocookie.com", "*.youtube-nocookie.com",
        ], &[], "youtube", ""),

        svc("spotify", "Spotify", "spotify", &[
            "spotify.com", "*.spotify.com",
            "scdn.co", "*.scdn.co",
            "spotifycdn.com", "*.spotifycdn.com",
            "audio-ak-spotify-com.akamaized.net",
        ], &[], "spotify", ""),

        svc("chatgpt", "ChatGPT", "chatgpt", &[
            "openai.com", "*.openai.com",
            "chatgpt.com", "*.chatgpt.com",
            "oaistatic.com", "*.oaistatic.com",
            "oaiusercontent.com", "*.oaiusercontent.com",
            "auth0.com", "*.auth0.com",
        ], &[], "openai", ""),

        svc("sora", "Sora", "sora", &[
            "sora.com", "*.sora.com",
            "openai.com", "*.openai.com",
        ], &[], "openai", ""),

        svc("meta-ai", "Meta AI", "meta-ai", &[
            "meta.ai", "*.meta.ai",
            "llama.com", "*.llama.com",
            "facebook.com", "*.facebook.com",
        ], &[], "", ""),

        svc("google-ai", "Google AI", "google-ai", &[
            "gemini.google.com", "ai.google.dev", "generativelanguage.googleapis.com",
            "aistudio.google.com", "alkalimakersuite-pa.clients6.google.com",
        ], &[], "", ""),

        svc("apple-ai", "Apple AI", "apple-ai", &[
            "apple-intelligence.com", "*.apple-intelligence.com",
            "apple.com", "*.apple.com",
        ], &[], "", ""),

        svc("claude", "Claude", "claude", &[
            "anthropic.com", "*.anthropic.com",
            "claude.ai", "*.claude.ai",
        ], &[], "", ""),

        svc("google-search", "Google Search", "google", &[
            "google.com", "*.google.com",
            "googleapis.com", "*.googleapis.com",
            "gstatic.com", "*.gstatic.com",
        ], &[], "google", ""),

        svc("google-play", "Google Play", "google-play", &[
            "play.google.com", "play.googleapis.com",
            "android.clients.google.com",
            "*.ggpht.com", "*.googleusercontent.com",
        ], &[], "google", ""),

        svc("steam", "Steam", "steam", &[
            "steampowered.com", "*.steampowered.com",
            "steamcommunity.com", "*.steamcommunity.com",
            "steamstatic.com", "*.steamstatic.com",
            "steamgames.com", "*.steamgames.com",
            "steamcontent.com", "*.steamcontent.com",
        ], &[], "steam", ""),

        svc("dazn", "DAZN", "dazn", &[
            "dazn.com", "*.dazn.com",
            "dazn-api.com", "*.dazn-api.com",
            "indazn.com", "*.indazn.com",
        ], &[], "dazn", ""),

        svc("bahamut", "Bahamut/动画疯", "bahamut", &[
            "gamer.com.tw", "*.gamer.com.tw",
            "bahamut.com.tw", "*.bahamut.com.tw",
            "hinet.net", "*.hinet.net",
        ], &[], "bahamut", ""),

        svc("bilibili", "Bilibili", "bilibili", &[
            "bilibili.com", "*.bilibili.com",
            "bilivideo.com", "*.bilivideo.com",
            "biliapi.net", "*.biliapi.net",
            "hdslb.com", "*.hdslb.com",
        ], &[], "bilibili", ""),

        svc("tiktok", "TikTok", "tiktok", &[
            "tiktok.com", "*.tiktok.com",
            "tiktokv.com", "*.tiktokv.com",
            "tiktokcdn.com", "*.tiktokcdn.com",
            "musical.ly", "*.musical.ly",
            "ibyteimg.com", "*.ibyteimg.com",
        ], &[], "tiktok", ""),

        svc("iqiyi", "iQiyi", "iqiyi", &[
            "iq.com", "*.iq.com",
            "iqiyi.com", "*.iqiyi.com",
            "71.am.com", "*.71.am.com",
        ], &[], "", ""),

        svc("nhk", "NHK+", "nhk", &[
            "nhk.or.jp", "*.nhk.or.jp",
            "nhk.jp", "*.nhk.jp",
        ], &[], "", ""),

        svc("unext", "U-NEXT", "unext", &[
            "unext.jp", "*.unext.jp",
            "nxtv.jp", "*.nxtv.jp",
        ], &[], "", ""),

        svc("tver", "TVer", "tver", &[
            "tver.jp", "*.tver.jp",
        ], &[], "", ""),

        svc("danimestore", "D Anime Store", "danimestore", &[
            "animestore.docomo.ne.jp", "*.animestore.docomo.ne.jp",
            "docomo.ne.jp",
        ], &[], "", ""),

        svc("fod", "FOD(Fuji TV)", "fod", &[
            "fod.fujitv.co.jp", "*.fod.fujitv.co.jp",
            "fujitv.co.jp", "*.fujitv.co.jp",
        ], &[], "", ""),

        svc("radiko", "Radiko", "radiko", &[
            "radiko.jp", "*.radiko.jp",
        ], &[], "", ""),

        svc("mytvsuper", "myTV SUPER", "mytvsuper", &[
            "mytvsuper.com", "*.mytvsuper.com",
            "mytv.com.hk", "*.mytv.com.hk",
        ], &[], "", ""),

        svc("jav", "JAV", "jav", &[
            "javbus.com", "*.javbus.com",
            "javdb.com", "*.javdb.com",
            "javlibrary.com", "*.javlibrary.com",
            "dmm.co.jp", "*.dmm.co.jp",
            "dmm.com", "*.dmm.com",
        ], &[], "dmm", ""),
    ]
}

fn svc(
    id: &str,
    name: &str,
    icon: &str,
    domains: &[&str],
    cidrs: &[&str],
    geosite: &str,
    geoip: &str,
) -> Service {
    Service {
        id: id.to_string(),
        name: name.to_string(),
        icon: icon.to_string(),
        enabled: false,
        domains: domains.iter().map(|s| s.to_string()).collect(),
        cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        geosite: geosite.to_string(),
        geoip: geoip.to_string(),
    }
}
