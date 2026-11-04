// Package services is a catalogue of well-known online services and the domains
// they use, so that a whole service can be blocked with one switch.
package services

import (
	"sort"

	"github.com/teliso/DNSentry/internal/dnsname"
)

// Service is one blockable service. Blocking it blocks every listed domain and
// all of their subdomains.
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Domains []string `json:"domains"`
}

const (
	Social    = "社交"
	Video     = "视频与音乐"
	Games     = "游戏"
	Messaging = "即时通讯"
)

// Catalog lists the services in display order.
var Catalog = []Service{
	{"tiktok", "TikTok", Video, []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com", "byteoversea.com", "ibytedtos.com", "musical.ly"}},
	{"douyin", "抖音", Video, []string{"douyin.com", "douyincdn.com", "douyinpic.com", "douyinvod.com", "iesdouyin.com", "douyinstatic.com"}},
	{"kuaishou", "快手", Video, []string{"kuaishou.com", "gifshow.com", "yximgs.com", "ksapisrv.com", "kwimgs.com"}},
	{"bilibili", "哔哩哔哩", Video, []string{"bilibili.com", "hdslb.com", "biliapi.net", "biliapi.com", "bilivideo.com", "b23.tv"}},
	{"youtube", "YouTube", Video, []string{"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt3.ggpht.com"}},
	{"netflix", "Netflix", Video, []string{"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"}},
	{"twitch", "Twitch", Video, []string{"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchapps.com"}},
	{"spotify", "Spotify", Video, []string{"spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi"}},

	{"facebook", "Facebook", Social, []string{"facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "facebook.net", "fb.me", "fbpigeon.com"}},
	{"instagram", "Instagram", Social, []string{"instagram.com", "cdninstagram.com", "instagr.am"}},
	{"twitter", "X (Twitter)", Social, []string{"twitter.com", "x.com", "twimg.com", "t.co", "twttr.com"}},
	{"reddit", "Reddit", Social, []string{"reddit.com", "redd.it", "redditstatic.com", "redditmedia.com", "reddituploads.com"}},
	{"snapchat", "Snapchat", Social, []string{"snapchat.com", "sc-cdn.net", "snap.com", "snapkit.com"}},
	{"pinterest", "Pinterest", Social, []string{"pinterest.com", "pinimg.com", "pin.it"}},
	{"weibo", "微博", Social, []string{"weibo.com", "weibo.cn", "sinaimg.cn"}},
	{"xiaohongshu", "小红书", Social, []string{"xiaohongshu.com", "xhscdn.com", "xhslink.com"}},
	{"zhihu", "知乎", Social, []string{"zhihu.com", "zhimg.com"}},

	{"whatsapp", "WhatsApp", Messaging, []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
	{"telegram", "Telegram", Messaging, []string{"telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe", "tdesktop.com"}},
	{"discord", "Discord", Messaging, []string{"discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media", "discordcdn.com"}},

	{"steam", "Steam", Games, []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steam-chat.com", "steamgames.com", "steamusercontent.com"}},
	{"epicgames", "Epic Games", Games, []string{"epicgames.com", "unrealengine.com", "epicgames.dev", "fortnite.com"}},
	{"roblox", "Roblox", Games, []string{"roblox.com", "rbxcdn.com", "robloxlabs.com"}},
	{"minecraft", "Minecraft", Games, []string{"minecraft.net", "mojang.com", "minecraftservices.com"}},
	{"genshin", "原神 / 米哈游", Games, []string{"mihoyo.com", "hoyoverse.com", "yuanshen.com", "hoyolab.com"}},
}

// Find returns the catalogue entry with the given id.
func Find(id string) (Service, bool) {
	for _, service := range Catalog {
		if service.ID == id {
			return service, true
		}
	}
	return Service{}, false
}

// Normalize drops unknown and duplicate ids and returns the rest in catalogue
// order. The second result lists the ids that were not recognised.
func Normalize(ids []string) (known, unknown []string) {
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := Find(id); ok {
			wanted[id] = true
		} else if id != "" {
			unknown = append(unknown, id)
		}
	}
	for _, service := range Catalog {
		if wanted[service.ID] {
			known = append(known, service.ID)
		}
	}
	sort.Strings(unknown)
	return known, unknown
}

// Matcher finds out whether a domain belongs to one of the selected services.
// It is immutable and safe for concurrent use.
type Matcher struct {
	byDomain map[string]Service
}

// NewMatcher builds a matcher for the given service ids (unknown ids are ignored).
func NewMatcher(ids []string) *Matcher {
	matcher := &Matcher{byDomain: map[string]Service{}}
	known, _ := Normalize(ids)
	for _, id := range known {
		service, _ := Find(id)
		for _, domain := range service.Domains {
			matcher.byDomain[domain] = service
		}
	}
	return matcher
}

// Match reports the selected service that owns domain or one of its parents.
func (m *Matcher) Match(domain string) (Service, bool) {
	if m == nil || len(m.byDomain) == 0 {
		return Service{}, false
	}
	for candidate := domain; candidate != ""; candidate = dnsname.Parent(candidate) {
		if service, ok := m.byDomain[candidate]; ok {
			return service, true
		}
	}
	return Service{}, false
}
