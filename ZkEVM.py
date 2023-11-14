import base64
import datetime
import json
import os
import random
import re
import ssl
import time
import traceback
from pathlib import Path
from typing import Generator

import capmonster_python
import cloudscraper
import pytest
import requests
import ua_generator
from logger import logger

from playwright.sync_api import sync_playwright, Playwright, BrowserContext, expect

class Discord:

    def __init__(self, token, proxy, cap_key):

        self.cap = capmonster_python.HCaptchaTask(cap_key)
        self.token = token
        self.proxy = proxy

        # print(token)
        # print(proxy)
        # print(cap_key)

        self.session = self._make_scraper()
        self.ua = ua_generator.generate(device="desktop").text
        self.session.user_agent = self.ua
        self.session.proxies = self.proxy
        self.super_properties = self.build_xsp(self.ua)


        self.cfruid, self.dcfduid, self.sdcfduid = self.fetch_cookies(self.ua)
        self.fingerprint = self.get_fingerprint()


    def JoinServer(self, invite):

        rer = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token})

        # print(rer.text, rer.status_code)
        # print(rer.text)
        # print(rer.status_code)

        if "200" not in str(rer):
            site = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
            tt = self.cap.create_task("https://discord.com/api/v9/invites/" + invite, site)
            # print(f"Created Captcha Task {tt}")
            captcha = self.cap.join_task_result(tt)
            captcha = captcha["gRecaptchaResponse"]
            # print(f"[+] Solved Captcha ")
            # print(rer.text)

            self.session.headers = {'Host': 'discord.com', 'Connection': 'keep-alive',
                               'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                               'X-Super-Properties': self.super_properties,
                               'Accept-Language': 'en-US', 'sec-ch-ua-mobile': '?0',
                               "User-Agent": self.ua,
                               'Content-Type': 'application/json', 'Authorization': 'undefined', 'Accept': '*/*',
                               'Origin': 'https://discord.com', 'Sec-Fetch-Site': 'same-origin',
                               'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
                               'Referer': 'https://discord.com/@me', 'X-Debug-Options': 'bugReporterEnabled',
                               'Accept-Encoding': 'gzip, deflate, br',
                               'x-fingerprint': self.fingerprint,
                               'Cookie': f'__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; __cf_bm=DFyh.5fqTsl1JGyPo1ZFMdVTupwgqC18groNZfskp4Y-1672630835-0-Aci0Zz919JihARnJlA6o9q4m5rYoulDy/8BGsdwEUE843qD8gAm4OJsbBD5KKKLTRHhpV0QZybU0MrBBtEx369QIGGjwAEOHg0cLguk2EBkWM0YSTOqE63UXBiP0xqHGmRQ5uJ7hs8TO1Ylj2QlGscA='}
            rej = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}, json={
                "captcha_key": captcha,
                "captcha_rqtoken": str(rer.json()["captcha_rqtoken"])
            })
            # print(rej.text())
            # print(rej.status_code)
            if "200" in str(rej):
                return 'Successfully Join 0', self.super_properties
            if "200" not in str(rej):
                return 'Failed Join'

        else:
            with self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}) as response:
                # print(response.text)
                pass
            return 'Successfully Join 1', self.super_properties


    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    def build_xsp(self, ua):
        # ua = get_useragent()
        _,fv = self.get_version(ua)
        data = json.dumps({
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": ua,
            "browser_version": fv,
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": self.get_buildnumber(),
            "client_event_source": None
        }, separators=(",",":"))
        return base64.b64encode(data.encode()).decode()

    def get_version(self, user_agent):  # Just splits user agent
        chrome_version = user_agent.split("/")[3].split(".")[0]
        full_chrome_version = user_agent.split("/")[3].split(" ")[0]
        return chrome_version, full_chrome_version

    def get_buildnumber(self):  # Todo: make it permanently work
        r = requests.get('https://discord.com/app', headers={'User-Agent': 'Mozilla/5.0'})
        asset = re.findall(r'([a-zA-z0-9]+)\.js', r.text)[-2]
        assetFileRequest = requests.get(f'https://discord.com/assets/{asset}.js',
                                        headers={'User-Agent': 'Mozilla/5.0'}).text
        try:
            build_info_regex = re.compile('buildNumber:"[0-9]+"')
            build_info_strings = build_info_regex.findall(assetFileRequest)[0].replace(' ', '').split(',')
        except:
            # print("[-]: Failed to get build number")
            pass
        dbm = build_info_strings[0].split(':')[-1]
        return int(dbm.replace('"', ""))

    def fetch_cookies(self, ua):
        try:
            url = 'https://discord.com/'
            headers = {'user-agent': ua}
            response = self.session.get(url, headers=headers, proxies=self.proxy)
            cookies = response.cookies.get_dict()
            cfruid = cookies.get("__cfruid")
            dcfduid = cookies.get("__dcfduid")
            sdcfduid = cookies.get("__sdcfduid")
            return cfruid, dcfduid, sdcfduid
        except:
            # print(response.text)
            return 1

    def get_fingerprint(self):
        try:
            fingerprint = self.session.get('https://discord.com/api/v9/experiments', proxies=self.proxy).json()['fingerprint']
            # print(f"[=]: Fetched Fingerprint ({fingerprint[:15]}...)")
            return fingerprint
        except Exception as err:
            # print(err)
            return 1



def acp_api_send_request(page, message_type, data={}):
    message = {
        # всегда указывается именно этот получатель API сообщения
        'receiver': 'antiCaptchaPlugin',
        # тип запроса, например setOptions
        'type': message_type,

        # мерджим с дополнительными данными
        **data
    }
    # выполняем JS код на странице
    # а именно отправляем сообщение стандартным методом window.postMessage

    page.evaluate("""
        window.postMessage({});
        """.format(json.dumps(message)))

    return True

@pytest.fixture()
def context(playwright: Playwright) -> Generator[BrowserContext, None, None]:
    path_to_extension = Path(__file__).parent.joinpath('10.32.0_0')
    print(path_to_extension)
    context = playwright.chromium.launch_persistent_context(
        "",
        headless=False,
        args=[
            f"--disable-extensions-except={path_to_extension}",
            f"--load-extension={path_to_extension}",
        ],
    )
    yield context
    context.close()

@pytest.fixture()
def extension_id(context) -> Generator[str, None, None]:
    # for manifest v2:
    # background = context.background_pages[0]
    # if not background:
    #     background = context.wait_for_event("backgroundpage")

    # for manifest v3:
    background = context.service_workers[0]
    if not background:
        background = context.wait_for_event("serviceworker")

    extension_id = background.url.split("/")[2]
    yield extension_id

class PWModel:

    def __init__(self, private, proxy, auth_token, ct0, DStoken, capKey):
        self.playwright = sync_playwright().start()

        self.auth_token, self.ct0, self.DStoken, self.CapKey = auth_token, ct0, DStoken, capKey
        self.privateKey,self.proxy = private, proxy

        EX_path = 'MetaMask'
        user_data_dir = f"{os.getcwd()}\\dataDir"

        self.proxies = {
            "http": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}",
            "https": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}"}

        self.context = self.playwright.chromium.launch_persistent_context(user_data_dir,
                                                                          user_agent=ua_generator.generate(platform="macos").text,
                                                                     proxy={
            "server": f"{proxy.split(':')[0]}:{proxy.split(':')[1]}",
            "username": f"{proxy.split(':')[2]}",
            "password": f"{proxy.split(':')[3]}",
        },headless=False, devtools=False, args=[f'--load-extension={os.getcwd()}\\{EX_path}',
                                               f'--disable-extensions-except={os.getcwd()}\\{EX_path}'
                                               ])

        self.page = self.context.new_page()

        self.page.set_default_timeout(60000)




    def MMActivation(self):
        # Открытие страницы Twitter
        self.page.goto('https://google.com')
        self.page.wait_for_timeout(5000)

        # print(self.context.pages)

        self.MMPage = self.context.pages[-1]
        self.MMPage.reload()
        self.MMPage.wait_for_selector('input[id="onboarding__terms-checkbox"]').click()
        self.MMPage.wait_for_selector('button[data-testid="onboarding-create-wallet"]').click()
        self.MMPage.wait_for_selector('button[data-testid="metametrics-i-agree"]').click()
        self.MMPage.wait_for_selector('input[data-testid="create-password-new"]').fill('Passwordsdjeruf039fnreo')
        self.MMPage.wait_for_selector('input[data-testid="create-password-confirm"]').fill('Passwordsdjeruf039fnreo')
        self.MMPage.wait_for_selector('input[data-testid="create-password-terms"]').click()
        self.MMPage.wait_for_selector('button[data-testid="create-password-wallet"]').click()
        self.MMPage.wait_for_selector('button[data-testid="secure-wallet-later"]').click()
        self.MMPage.wait_for_selector('input[data-testid="skip-srp-backup-popover-checkbox"]').click()
        self.MMPage.wait_for_selector('button[data-testid="skip-srp-backup"]').click()
        self.MMPage.wait_for_selector('button[data-testid="onboarding-complete-done"]').click()
        self.MMPage.wait_for_selector('button[data-testid="pin-extension-next"]').click()
        self.MMPage.wait_for_timeout(1000)
        self.MMPage.wait_for_selector('button[data-testid="pin-extension-done"]').click()
        self.MMPage.wait_for_timeout(4000)
        self.MMPage.wait_for_selector('button[data-testid="popover-close"]').click()
        # self.MMPage.wait_for_timeout(1000)
        # self.MMPage.wait_for_selector('button[data-testid="popover-close"]').click()
        self.MMPage.wait_for_timeout(1000)
        self.MMPage.wait_for_selector('button[data-testid="account-menu-icon"]').click()
        self.MMPage.wait_for_selector('div.account-menu > button.account-menu__item.account-menu__item--clickable')
        self.MMPage.query_selector_all('div.account-menu > button.account-menu__item.account-menu__item--clickable')[1].click()
        self.MMPage.wait_for_selector('input[id="private-key-box"]').fill(self.privateKey)
        self.MMPage.wait_for_selector('xpath=//*[@id="app-content"]/div/div[3]/div/div[2]/div[2]/button[2]').click()
        self.MMPage.wait_for_selector('button[data-testid="eth-overview-send"]')

    def Login(self):

        self.page.bring_to_front()
        self.page.goto('https://quest.intract.io/quest/64b7a6b0b549e0360fa6456d', timeout=120000)

        pages_len = len(self.context.pages)
        self.page.wait_for_selector('div.nav-menu-button-holder > span').click()
        self.page.wait_for_selector('img[src="/assets/img/wallets/metamask.svg"]').click()
        while pages_len == len(self.context.pages):
            self.page.wait_for_timeout(1000)

        self.MMAdditionalPage = self.context.pages[-1]
        self.MMAdditionalPage.wait_for_selector('button.btn-primary').click()
        self.MMAdditionalPage.wait_for_selector('button[data-testid="page-container-footer-next"]').click()

        self.MMAdditionalPage.wait_for_timeout(5000)

        self.MMAdditionalPage = self.context.pages[-1]
        self.MMAdditionalPage.wait_for_selector('button[data-testid="page-container-footer-next"]').click()

    def Task1(self):

        self.page.wait_for_selector('xpath=//p[text()="Connect wallet and sign a message"]').click()
        self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
        self.page.wait_for_selector('div.tab-link-holder').click()
        self.page.wait_for_selector('div.modal-body.position-relative div.button.pointer.dark').click()
        self.page.wait_for_timeout(3000)

    def Task2(self):
        # o = json.dumps([{"domain": ".twitter.com", "name": "auth_token", "path": "/", "value": self.auth_token},
        #                 {"domain": ".twitter.com", "name": "ct0", "path": "/", "value": self.ct0}])
        # self.context.add_cookies(json.loads(o))

        self.page.wait_for_selector('xpath=//p[text()="Follow @0xPolygonDeFi on Twitter"]').click()

        pages_len = len(self.context.pages)
        self.page.wait_for_selector('.mt-5 img[src="/assets/img/brands/twitter.png"]').click()
        while pages_len == len(self.context.pages):
            self.page.wait_for_timeout(1000)

        self.twitterPage = self.context.pages[-1]
        self.twitterPage.bring_to_front()


        self.page.wait_for_timeout(10000000)

        while True:

            try:
                self.twitterPage.wait_for_selector('div[aria-live="polite"]', timeout=30000).click()
                try:
                    self.twitterPage.wait_for_selector('div.modal-body.position-relative div.button.pointer.dark').click()
                except:
                    pass

                break

            except:

                try:

                    self.twitterPage.close()
                except:
                    pass

                self.page.wait_for_timeout(2000)

                pages_len = len(self.context.pages)
                self.page.wait_for_selector('button[aria-label="Retry"]').click()
                while pages_len == len(self.context.pages):
                    self.page.wait_for_timeout(1000)
                self.twitterPage = self.context.pages[-1]
                self.twitterPage.bring_to_front()


        self.page.wait_for_timeout(3000)

        pages_len = len(self.context.pages)
        self.page.wait_for_selector('xpath=//p[text()="Follow @0xPolygonDeFi on Twitter"]').click()
        while pages_len == len(self.context.pages):
            self.page.wait_for_timeout(1000)

        self.twitterPage = self.context.pages[-1]
        self.twitterPage.bring_to_front()

        self.twitterPage.wait_for_selector('div[data-testid="confirmationSheetConfirm"]').click()
        self.twitterPage.wait_for_timeout(3000)
        self.twitterPage.close()

        self.page.bring_to_front()
        self.page.wait_for_timeout(10000)
        self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
        try:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden", timeout=10000)
        except:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
            try:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden",
                                            timeout=10000)
            except:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()

    def Task3(self):

        pages_len = len(self.context.pages)
        self.page.wait_for_selector('xpath=//p[text()="Follow @IntractCampaign on Twitter"]').click()
        while pages_len == len(self.context.pages):
            self.page.wait_for_timeout(1000)

        self.twitterPage = self.context.pages[-1]
        self.twitterPage.bring_to_front()

        self.twitterPage.wait_for_selector('div[data-testid="confirmationSheetConfirm"]').click()
        self.twitterPage.wait_for_timeout(3000)
        self.twitterPage.close()

        self.page.bring_to_front()
        self.page.wait_for_timeout(10000)
        self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
        try:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden", timeout=10000)
        except:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
            try:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden",
                                            timeout=10000)
            except:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
    def Task4(self):

        nowPages = len(self.context.pages)

        self.page.wait_for_timeout(2000)
        self.page.wait_for_selector('xpath=//p[text()="Join a Discord Server"]').click()
        self.page.wait_for_selector('.mt-5 img[src="/assets/img/brands/discord.png"]').click()
        self.page.wait_for_timeout(5000)

        # for i in self.context.pages:
        #     print(i.url)

        # logger.info('qwweq')
        self.page.wait_for_timeout(5000)
        # logger.info('qwweq')
        self.DS_page_connector = None
        for i in self.context.pages:
            if 'discord.com' in i.url:
                self.DS_page_connector = i
                break

        logger.info('qwweq')
        self.DS_page_connector.evaluate(f'''() => {{
                                function login(token) {{
                                    setInterval(() => {{
                                        document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"${{token}}"`
                                    }}, 50);
                                    setTimeout(() => {{
                                        location.reload();
                                    }}, 2500);
                                }}
                                    login('{self.DStoken}');
                            }}''')

        self.DS_page_connector.wait_for_selector('button[type="button"][class*="colorBrand"]').click(timeout=15000)


        self.page.wait_for_timeout(5000)
        self.page.wait_for_selector('xpath=//p[text()="Join a Discord Server"]').click()

        try:
            Discord(self.DStoken, self.proxies, self.CapKey).JoinServer('8NEBvmAbDN')
        except:
            self.page.wait_for_timeout(10000)

        # self.page.wait_for_timeout(11000)
        self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
        try:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden", timeout=10000)
        except:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
            try:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden",
                                            timeout=10000)
            except:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()

    def Task5(self):

        pages_len = len(self.context.pages)
        self.page.wait_for_selector('xpath=//p[text()="Post a Tweet with hashtags #PolygonzkEVM and #Intract"]').click()

        while pages_len == len(self.context.pages):
            self.page.wait_for_timeout(1000)

        self.twitterPage = self.context.pages[-1]
        self.twitterPage.bring_to_front()

        self.twitterPage.wait_for_selector('div[data-testid="tweetButton"]').click()
        self.twitterPage.wait_for_timeout(3000)
        self.twitterPage.close()

        self.page.bring_to_front()
        self.page.wait_for_timeout(10000)
        self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
        try:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden", timeout=10000)
        except:
            self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
            try:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white', state="hidden",
                                            timeout=10000)
            except:
                self.page.wait_for_selector('div.task-content-holder div.form > div.white').click()
        self.page.wait_for_timeout(3000)

    def GetNFT(self):

        pages_len = len(self.context.pages)
        self.page.wait_for_timeout(4000)
        self.page.wait_for_selector('xpath=//*[@id="reward-card"]/div[4]/div/div/div[2]').click()
        while pages_len == len(self.context.pages):
            self.page.wait_for_timeout(1000)

        self.MMAdditionalPage = self.context.pages[-1]
        self.MMAdditionalPage.bring_to_front()
        self.MMAdditionalPage.wait_for_selector('button.btn-primary').click()
        self.page.wait_for_timeout(2000)
        self.MMAdditionalPage.wait_for_selector('button.btn-primary').click()

        self.MMAdditionalPage.wait_for_timeout(5000)
        self.MMAdditionalPage = self.context.pages[-1]

        self.MMAdditionalPage.wait_for_selector('button[data-testid="page-container-footer-next"]').click()
        self.page.bring_to_front()
        self.page.wait_for_selector('xpath=//*[@id="reward-card"]/div[4]/div/div/div[1]', state="hidden")
        self.page.wait_for_timeout(5000)


    def close(self):

        self.playwright.stop()

if __name__ == '__main__':

    start_time = time.time()
    try:


        Model = PWModel(private = '',
                        proxy = '',
                        auth_token = '',
                        ct0 = '',
                        DStoken = '',
                        capKey = '')

        Model.MMActivation()
        logger.success('Метамаск активирован')
        Model.Login()
        logger.success('Успешно залогинились на сайт')

        # Model.Task1()
        # logger.success('Задание 1 решено')
        Model.Task2()
        logger.success('Задание 2 решено')
        Model.Task3()
        logger.success('Задание 3 решено')
        Model.Task4()
        logger.success('Задание 4 решено')
        Model.Task5()
        logger.success('Задание 5 решено')
        Model.GetNFT()
        logger.success('NFT Забрали')


        print('Готово')


    except:
        traceback.print_exc()


    end_time = time.time()

    execution_time = end_time - start_time
    print(f"Время выполнения скрипта: {execution_time} секунд")
    Model.page.wait_for_timeout(10000000)

