import json
import random
import asyncio
import aiohttp
from web3 import Web3
from fake_useragent import UserAgent
import logging
from logging.handlers import RotatingFileHandler
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import binascii
from datetime import datetime, timedelta


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class Logger:
    def __init__(self, log_file='kiteai_bot.log', max_bytes=10 * 1024 * 1024, backup_count=5):
        self.logger = logging.getLogger('KiteAIBot')
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def info(self, account_index, msg):
        self.logger.info(f"[Account {account_index}] {msg}")
        print(f"{Colors.GREEN}[{account_index}] {msg}{Colors.RESET}")

    def wallet(self, account_index, msg):
        self.logger.info(f"[Account {account_index}] {msg}")
        print(f"{Colors.YELLOW}[{account_index}] {msg}{Colors.RESET}")

    def error(self, account_index, msg):
        self.logger.error(f"[Account {account_index}] {msg}")
        print(f"{Colors.RED}[{account_index}] {msg}{Colors.RESET}")

    def success(self, account_index, msg):
        self.logger.info(f"[Account {account_index}] {msg}")
        print(f"{Colors.GREEN}[{account_index}] {msg}{Colors.RESET}")

    def loading(self, account_index, msg):
        self.logger.info(f"[Account {account_index}] {msg}")
        print(f"{Colors.CYAN}[{account_index}] {msg}{Colors.RESET}")

    def step(self, account_index, msg):
        self.logger.info(f"[Account {account_index}] {msg}")
        print(f"{Colors.WHITE}[{account_index}] {msg}{Colors.RESET}")

    def agent(self, account_index, msg):
        self.logger.info(f"[Account {account_index}] {msg}")
        print(f"{Colors.WHITE}[{account_index}] {msg}{Colors.RESET}")

    def banner(self):
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("---------------------------------------------")
        print("     SOSAL?")
        print(f"---------------------------------------------{Colors.RESET}\n")


class Config:
    def __init__(self):
        self.TWO_CAPTCHA_API_KEY = "YOUR_TWO_CAPTCHA_API_KEY"
        self.MIN_INTERACTIONS = 3
        self.MAX_INTERACTIONS = 8
        self.MAX_WORKERS = 5
        self.KITE_AI_SUBNET = "0xb132001567650917d6bd695d1fab55db7986e9a5"
        self.AGENTS = [
            {"name": "Professor", "service_id": "deployment_KiMLvUiTydioiHm7PWZ12zJU"},
            {"name": "Crypto Buddy", "service_id": "deployment_ByVHjMD6eDb9AdekRIbyuz14"},
            {"name": "Sherlock", "service_id": "deployment_OX7sn2D0WvxGUGK8CTqsU5VJ"}
        ]
        self.BASE_HEADERS = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Origin": "https://testnet.gokite.ai",
            "Referer": "https://testnet.gokite.ai/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Content-Type": "application/json"
        }


class StateManager:
    def __init__(self, state_file="state.json"):
        self.state_file = state_file

    def load(self):
        try:
            with open(self.state_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save(self, state):
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)


class UserAgentManager:
    def __init__(self, ua_file="ua.json"):
        self.ua_file = ua_file
        self.ua_generator = UserAgent()

    def load(self):
        try:
            with open(self.ua_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save(self, account, ua):
        ua_dict = self.load()
        ua_dict[account] = ua
        with open(self.ua_file, "w") as f:
            json.dump(ua_dict, f, indent=2)

    def get(self, account):
        ua_dict = self.load()
        return ua_dict.get(account, self.ua_generator.random)


class AccountManager:
    def __init__(self, accounts_file="accounts.txt", proxies_file="proxies.txt"):
        self.accounts_file = accounts_file
        self.proxies_file = proxies_file

    def load_accounts(self, logger):
        try:
            with open(self.accounts_file, "r") as f:
                accounts = []
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(":")
                        private_key = parts[0]
                        neo_session = parts[1] if len(parts) > 1 and parts[1] else None
                        refresh_token = parts[2] if len(parts) > 2 and parts[2] else None
                        accounts.append(
                            {"private_key": private_key, "neo_session": neo_session, "refresh_token": refresh_token})
                return accounts
        except Exception as e:
            logger.error(0, f"Ошибка загрузки accounts.txt: {e}")
            return []

    def load_proxies(self, logger):
        try:
            with open(self.proxies_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(0, f"Ошибка загрузки proxies.txt: {e}")
            return []


class Wallet:
    def __init__(self, account_index, private_key, logger):
        self.account_index = account_index
        self.logger = logger
        self.account = self._create_wallet(private_key)

    def _create_wallet(self, private_key):
        try:
            w3 = Web3()
            account = w3.eth.account.from_key(private_key)
            self.logger.info(self.account_index, f"Кошелек создан: {account.address}")
            return account
        except Exception as e:
            self.logger.error(self.account_index, f"Неверный приватный ключ: {e}")
            return None

    @property
    def address(self):
        return self.account.address if self.account else None


class KiteAIClient:
    def __init__(self, account_index, wallet, neo_session, refresh_token, proxy, config, logger):
        self.account_index = account_index
        self.wallet = wallet
        self.neo_session = neo_session
        self.refresh_token = refresh_token
        self.proxy = proxy
        self.config = config
        self.logger = logger
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def check_proxy(self):
        test_url = "https://api.ipify.org"
        for attempt in range(5):
            try:
                async with self.session.get(test_url, proxy=self.proxy, timeout=10) as response:
                    if response.status == 200:
                        self.logger.step(self.account_index, f"Прокси {self.proxy} рабочий")
                        return True
            except Exception as e:
                self.logger.error(self.account_index, f"Прокси {self.proxy} не работает (попытка {attempt + 1}/5): {e}")
                await asyncio.sleep(2)
        return False

    def _encrypt_address(self, address):
        try:
            key_hex = "6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a"
            key = binascii.unhexlify(key_hex)
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(address.encode()) + encryptor.finalize()
            auth_tag = encryptor.tag
            result = iv + encrypted + auth_tag
            return base64.b16encode(result).decode().lower()
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка генерации токена авторизации для {address}: {e}")
            return None

    def _extract_cookies(self, headers):
        try:
            cookies = headers.get("set-cookie", [])
            skip_keys = ["expires", "path", "domain", "samesite", "secure", "httponly", "max-age"]
            cookies_dict = {}
            for cookie in cookies:
                for part in cookie.split(";"):
                    part = part.strip()
                    if "=" in part:
                        name, value = part.split("=", 1)
                        if name.lower() not in skip_keys:
                            cookies_dict[name] = value
            return "; ".join(f"{k}={v}" for k, v in cookies_dict.items()) or None
        except Exception:
            self.logger.error(self.account_index, "Ошибка извлечения кук")
            return None

    async def solve_recaptcha(self, url, max_retries=3):
        site_key = "6Lc_VwgrAAAAALtx_UtYQnW-cFg8EPDgJ8QVqkaz"
        for attempt in range(max_retries):
            try:
                self.logger.loading(self.account_index,
                                    f"Решаем reCAPTCHA с 2Captcha (попытка {attempt + 1}/{max_retries})")
                request_url = f"http://2captcha.com/in.php?key={self.config.TWO_CAPTCHA_API_KEY}&method=userrecaptcha&googlekey={site_key}&pageurl={url}&json=1"
                async with self.session.get(request_url, proxy=self.proxy) as response:
                    data = await response.json()
                    if data["status"] != 1:
                        self.logger.error(self.account_index,
                                          f"Ошибка отправки задачи reCAPTCHA: {data.get('error_text')}")
                        if attempt == max_retries - 1:
                            return None
                        await asyncio.sleep(5)
                        continue
                request_id = data["request"]
                self.logger.step(self.account_index, f"Задача reCAPTCHA отправлена, ID: {request_id}")
                for _ in range(30):
                    await asyncio.sleep(5)
                    result_url = f"http://2captcha.com/res.php?key={self.config.TWO_CAPTCHA_API_KEY}&action=get&id={request_id}&json=1"
                    async with self.session.get(result_url, proxy=self.proxy) as result_response:
                        result = await result_response.json()
                        if result["status"] == 1:
                            self.logger.success(self.account_index, "reCAPTCHA успешно решена")
                            return result["request"]
                        if result["request"] == "ERROR_CAPTCHA_UNSOLVABLE":
                            self.logger.error(self.account_index, "reCAPTCHA неразрешима")
                            break
                if attempt == max_retries - 1:
                    return None
            except Exception as e:
                self.logger.error(self.account_index, f"Ошибка решения reCAPTCHA: {e}")
                if attempt == max_retries - 1:
                    return None
                await asyncio.sleep(5)
        self.logger.error(self.account_index, "Не удалось решить reCAPTCHA после максимального количества попыток")
        return None

    async def login(self, user_agent):
        url = "https://neo.prod.gokite.ai/v2/signin"
        headers = {**self.config.BASE_HEADERS, "User-Agent": user_agent.get('user_agent', str(user_agent))}
        for attempt in range(3):
            try:
                self.logger.loading(self.account_index, f"Вход для {self.wallet.address} (попытка {attempt + 1}/3)")
                auth_token = self._encrypt_address(self.wallet.address)
                if not auth_token:
                    return None
                headers["Authorization"] = auth_token
                if self.neo_session or self.refresh_token:
                    cookies = []
                    if self.neo_session:
                        cookies.append(f"neo_session={self.neo_session}")
                    if self.refresh_token:
                        cookies.append(f"refresh_token={self.refresh_token}")
                    headers["Cookie"] = "; ".join(cookies)
                body = {"eoa": self.wallet.address}
                async with self.session.post(url, json=body, headers=headers, proxy=self.proxy) as response:
                    data = await response.json()
                    if data.get("error"):
                        self.logger.error(self.account_index,
                                          f"Ошибка входа для {self.wallet.address}: {data['error']}")
                        return None
                    cookies = self._extract_cookies(dict(response.headers))
                    access_token = data["data"]["access_token"]
                    aa_address = data["data"]["aa_address"]
                    displayed_name = data["data"]["displayed_name"]
                    avatar_url = data["data"]["avatar_url"]
                    if not aa_address:
                        profile = await self.get_user_profile(access_token)
                        aa_address = profile["profile"]["smart_account_address"] if profile else None
                        if not aa_address:
                            self.logger.error(self.account_index, f"Не найден aa_address для {self.wallet.address}")
                            return None
                    self.logger.success(self.account_index, f"Успешный вход для {self.wallet.address}")
                    return {"access_token": access_token, "aa_address": aa_address, "displayed_name": displayed_name,
                            "avatar_url": avatar_url, "cookie_header": cookies}
            except Exception as e:
                if attempt == 2:
                    self.logger.error(self.account_index,
                                      f"Ошибка входа для {self.wallet.address} после 3 попыток: {e}")
                    return None
                await asyncio.sleep(2)
        return None

    async def get_user_profile(self, access_token):
        try:
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            async with self.session.get("https://ozone-point-system.prod.gokite.ai/me", headers=headers,
                                        proxy=self.proxy) as response:
                data = await response.json()
                if data.get("error"):
                    self.logger.error(self.account_index, f"Ошибка получения профиля: {data['error']}")
                    return None
                if not data.get("data"):
                    self.logger.error(self.account_index, "Ошибка получения профиля: ответ API не содержит данных")
                    return None
                return data["data"]
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка получения профиля: {e}")
            return None

    async def claim_daily_faucet(self, access_token, cookie_header, state_manager):
        state = state_manager.load()
        last_faucet = state.get(self.wallet.address, {}).get("last_faucet")
        if last_faucet:
            last_faucet_time = datetime.fromisoformat(last_faucet)
            if datetime.now() - last_faucet_time < timedelta(hours=24):
                self.logger.info(self.account_index, "Faucet уже клеймлен сегодня, пропускаем")
                return False

        try:
            self.logger.loading(self.account_index, "Попытка клейма ежедневного faucet...")
            page_url = "https://testnet.gokite.ai"
            recaptcha_token = await self.solve_recaptcha(page_url)
            if not recaptcha_token:
                self.logger.error(self.account_index, "Не удалось получить токен reCAPTCHA")
                return False
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}",
                       "x-recaptcha-token": recaptcha_token}
            if cookie_header:
                headers["Cookie"] = cookie_header
            async with self.session.post("https://ozone-point-system.prod.gokite.ai/blockchain/faucet-transfer",
                                         json={}, headers=headers, proxy=self.proxy) as response:
                data = await response.json()
                if data.get("error"):
                    if "Already claimed" in data["error"].lower():
                        self.logger.info(self.account_index, "Faucet уже клеймлен сегодня")
                        state[self.wallet.address] = state.get(self.wallet.address, {})
                        state[self.wallet.address]["last_faucet"] = datetime.now().isoformat()
                        state_manager.save(state)
                    else:
                        self.logger.error(self.account_index, f"Ошибка клейма faucet: {data['error']}")
                    return False
            self.logger.success(self.account_index, "Ежедневный faucet успешно клеймлен")
            state[self.wallet.address] = state.get(self.wallet.address, {})
            state[self.wallet.address]["last_faucet"] = datetime.now().isoformat()
            state_manager.save(state)
            return True
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка клейма faucet: {e}")
            return False

    async def get_stake_info(self, access_token, cookie_header):
        try:
            self.logger.loading(self.account_index, "Получение информации о стейкинге...")
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            if cookie_header:
                headers["Cookie"] = cookie_header
            async with self.session.get("https://ozone-point-system.prod.gokite.ai/subnet/3/staked-info?id=3",
                                        headers=headers, proxy=self.proxy) as response:
                data = await response.json()
                if data.get("error"):
                    self.logger.error(self.account_index, f"Ошибка получения информации о стейкинге: {data['error']}")
                    return None
                return data["data"]
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка получения информации о стейкинге: {e}")
            return None

    async def stake_token(self, access_token, cookie_header, max_retries=3):
        for attempt in range(max_retries):
            try:
                self.logger.loading(self.account_index,
                                    f"Попытка стейкинга 1 токена KITE (попытка {attempt + 1}/{max_retries})...")
                headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
                if cookie_header:
                    headers["Cookie"] = cookie_header
                payload = {"subnet_address": self.config.KITE_AI_SUBNET, "amount": 1}
                async with self.session.post("https://ozone-point-system.prod.gokite.ai/subnet/delegate", json=payload,
                                             headers=headers, proxy=self.proxy) as response:
                    data = await response.json()
                    if data.get("error"):
                        self.logger.error(self.account_index, f"Ошибка стейкинга: {data['error']}")
                        if attempt == max_retries - 1:
                            return False
                        await asyncio.sleep(5)
                        continue
                self.logger.success(self.account_index, "Успешно застейкано 1 токен KITE")
                return True
            except Exception as e:
                self.logger.error(self.account_index, f"Ошибка стейкинга: {e}")
                if attempt == max_retries - 1:
                    return False
                await asyncio.sleep(5)
        return False

    async def claim_stake_rewards(self, access_token, cookie_header):
        try:
            self.logger.loading(self.account_index, "Попытка клейма наград за стейкинг...")
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            if cookie_header:
                headers["Cookie"] = cookie_header
            payload = {"subnet_address": self.config.KITE_AI_SUBNET}
            async with self.session.post("https://ozone-point-system.prod.gokite.ai/subnet/claim-rewards", json=payload,
                                         headers=headers, proxy=self.proxy) as response:
                data = await response.json()
                if data.get("error"):
                    if "No reward to claim" in data["error"].lower():
                        self.logger.info(self.account_index, "Нет наград для клейма")
                    else:
                        self.logger.error(self.account_index, f"Ошибка клейма наград: {data['error']}")
                    return False
                reward = data["data"].get("claim_amount", 0)
                self.logger.success(self.account_index, f"Успешно клеймлено {reward} KITE наград")
                return True
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка клейма наград: {e}")
            return False

    async def interact_with_agent(self, access_token, aa_address, cookie_header, agent, prompt, interaction_count):
        try:
            if not aa_address:
                self.logger.error(self.account_index, f"Не удалось взаимодействовать с {agent['name']}: нет aa_address")
                return None
            self.logger.step(self.account_index, f"Взаимодействие {interaction_count} - Промпт: {prompt}")
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}",
                       "Accept": "text/event-stream"}
            if cookie_header:
                headers["Cookie"] = cookie_header
            async with self.session.post("https://ozone-point-system.prod.gokite.ai/agent/inference", json={
                "service_id": agent["service_id"],
                "subnet": "kite_ai_labs",
                "stream": True,
                "body": {"stream": True, "message": prompt}
            }, headers=headers, proxy=self.proxy) as response:
                output = ""
                async for line in response.content:
                    line = line.decode().strip()
                    if line.startswith("data: ") and line != "data: [DONE]":
                        try:
                            data = json.loads(line[6:])
                            if data.get("choices") and data["choices"][0]["delta"].get("content"):
                                output += data["choices"][0]["delta"]["content"]
                                if len(output) > 100:
                                    output = output[:100] + "..."
                                    break
                        except json.JSONDecodeError:
                            pass
            receipt_headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            if cookie_header:
                receipt_headers["Cookie"] = cookie_header
            async with self.session.post("https://neo.prod.gokite.ai/v2/submit_receipt", json={
                "address": aa_address,
                "service_id": agent["service_id"],
                "input": [{"type": "text/plain", "value": prompt}],
                "output": [{"type": "text/plain", "value": output or "No response"}]
            }, headers=receipt_headers, proxy=self.proxy) as receipt_response:
                receipt_data = await receipt_response.json()
                if receipt_data.get("error"):
                    self.logger.error(self.account_index,
                                      f"Ошибка отправки чека для {agent['name']}: {receipt_data['error']}")
                    return None
                receipt_id = receipt_data["data"]["id"]
                self.logger.step(self.account_index,
                                 f"Взаимодействие {interaction_count} - Чек отправлен, ID: {receipt_id}")
                for attempt in range(10):
                    async with self.session.get(f"https://neo.prod.gokite.ai/v1/inference?id={receipt_id}",
                                                headers={**self.config.BASE_HEADERS,
                                                         "Authorization": f"Bearer {access_token}"},
                                                proxy=self.proxy) as status_response:
                        status_data = await status_response.json()
                        if status_data["data"].get("processed_at") and status_data["data"].get("tx_hash"):
                            self.logger.step(self.account_index,
                                             f"Взаимодействие {interaction_count} - Инференс обработан, tx_hash: {status_data['data']['tx_hash']}")
                            return status_data["data"]
                    await asyncio.sleep(2)
                self.logger.error(self.account_index, f"Статус инференса не завершен после 10 попыток")
                return None
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка взаимодействия с {agent['name']}: {e}")
            return None

    async def create_quiz(self, access_token, cookie_header, state_manager):
        state = state_manager.load()
        last_quiz = state.get(self.wallet.address, {}).get("last_quiz")
        if last_quiz:
            last_quiz_time = datetime.fromisoformat(last_quiz)
            if datetime.now() - last_quiz_time < timedelta(hours=24):
                self.logger.info(self.account_index, "Квиз уже выполнен сегодня, пропускаем")
                return None

        try:
            self.logger.loading(self.account_index, "Попытка создания ежедневного квиза...")
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            if cookie_header:
                headers["Cookie"] = cookie_header
            quiz_date = datetime.now().strftime("%Y-%m-%d")
            payload = {
                "title": f"daily_quiz_{quiz_date}",
                "num": 1,
                "eoa": self.wallet.address
            }
            async with self.session.post("https://neo.prod.gokite.ai/v2/quiz/create", json=payload, headers=headers,
                                         proxy=self.proxy) as response:
                data = await response.json()
                if data.get("error"):
                    self.logger.error(self.account_index, f"Ошибка создания квиза: {data['error']}")
                    return None
                quiz_id = data["data"]["quiz_id"]
                self.logger.success(self.account_index, f"Квиз успешно создан, ID: {quiz_id}")
                state[self.wallet.address] = state.get(self.wallet.address, {})
                state[self.wallet.address]["last_quiz"] = datetime.now().isoformat()
                state_manager.save(state)
                return quiz_id
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка создания квиза: {e}")
            return None

    async def get_quiz(self, quiz_id, access_token, cookie_header):
        try:
            self.logger.loading(self.account_index, f"Получение данных квиза {quiz_id}...")
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            if cookie_header:
                headers["Cookie"] = cookie_header
            params = {"id": quiz_id, "eoa": self.wallet.address}
            async with self.session.get("https://neo.prod.gokite.ai/v2/quiz/get", params=params, headers=headers,
                                        proxy=self.proxy) as response:
                data = await response.json()
                if data.get("error"):
                    self.logger.error(self.account_index, f"Ошибка получения квиза: {data['error']}")
                    return None
                quiz_data = data["data"]
                self.logger.step(self.account_index, f"Структура ответа API: {json.dumps(quiz_data, indent=2)}")
                if not isinstance(quiz_data.get("question"), list) or not quiz_data["question"]:
                    self.logger.error(self.account_index,
                                      f"Вопросы квиза не найдены или неверный формат: {quiz_data.get('question')}")
                    return None
                question = quiz_data["question"][0]
                options = question.get("options", [])
                if not isinstance(options, list):
                    self.logger.error(self.account_index, f"Варианты ответа не найдены или неверный формат: {options}")
                    return None
                # Парсим варианты как строки вида "Label|ID"
                option_labels = [opt.split("|")[0] if isinstance(opt, str) and "|" in opt else opt for opt in options]
                self.logger.step(self.account_index, f"Вопрос: {question.get('content', 'Нет вопроса')}")
                self.logger.step(self.account_index,
                                 f"Варианты: {', '.join(option_labels) if option_labels else 'Нет вариантов'}")
                self.logger.step(self.account_index, f"Правильный ответ: {question.get('answer', 'Нет ответа')}")
                return {
                    "quiz_id": quiz_data["quiz"].get("quiz_id", quiz_id),  # Оставляем int
                    "question_id": question.get("question_id", ""),  # Оставляем int
                    "answer": question.get("answer", "")
                }
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка получения квиза: {e}")
            return None

    async def submit_quiz_answer(self, quiz_id, question_id, answer, access_token, cookie_header):
        try:
            self.logger.loading(self.account_index, f"Отправка ответа на квиз {quiz_id}...")
            await asyncio.sleep(random.uniform(3, 10))  # Пауза, будто человек думает
            headers = {**self.config.BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            if cookie_header:
                headers["Cookie"] = cookie_header
            payload = {
                "quiz_id": quiz_id,  # Без str(), используем int
                "question_id": question_id,  # Без str(), используем int
                "answer": answer,
                "eoa": self.wallet.address,
                "finish": True
            }
            async with self.session.post("https://neo.prod.gokite.ai/v2/quiz/submit", json=payload, headers=headers,
                                         proxy=self.proxy) as response:
                if response.status != 200:
                    error_text = await response.text()
                    self.logger.error(self.account_index,
                                      f"Ошибка отправки ответа: {response.status}, сообщение: {error_text}")
                    return False
                data = await response.json()
                if data.get("error"):
                    self.logger.error(self.account_index, f"Ошибка отправки ответа: {data['error']}")
                    return False
                result = data["data"]["result"]
                if result == "RIGHT":
                    self.logger.success(self.account_index, "Ответ правильный!")
                else:
                    self.logger.error(self.account_index, f"Ответ неправильный: {result}")
                return result == "RIGHT"
        except Exception as e:
            self.logger.error(self.account_index, f"Ошибка отправки ответа: {e}")
            return False


class KiteAIBot:
    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.state_manager = StateManager()
        self.ua_manager = UserAgentManager()
        self.account_manager = AccountManager()

    async def load_prompts(self):
        try:
            with open("prompt.txt", "r", encoding="utf-8") as f:
                content = f.readlines()
            prompt_generators = {}
            current_agent = None
            for line in content:
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    current_agent = line[1:-1].strip()
                    prompt_generators[current_agent] = []
                elif line and not line.startswith("#") and current_agent:
                    prompt_generators[current_agent].append(line)
            for agent in self.config.AGENTS:
                if agent["name"] not in prompt_generators or not prompt_generators[agent["name"]]:
                    self.logger.error(0, f"Промпты для агента {agent['name']} не найдены в prompt.txt")
                    raise SystemExit(1)
            return prompt_generators
        except Exception as e:
            self.logger.error(0, f"Ошибка загрузки prompt.txt: {e}")
            raise SystemExit(1)

    def get_random_prompt(self, agent_name, prompt_generators):
        prompts = prompt_generators.get(agent_name, [])
        return random.choice(prompts) if prompts else None

    async def process_account(self, account_index, account, proxy, prompt_generators, semaphore):
        async with semaphore:
            try:
                self.logger.wallet(account_index, f"Обработка кошелька: {account['private_key'][:10]}...")
                wallet = Wallet(account_index, account["private_key"], self.logger)
                if not wallet.account:
                    return

                async with KiteAIClient(account_index, wallet, account["neo_session"], account["refresh_token"], proxy,
                                        self.config, self.logger) as client:
                    if not await client.check_proxy():
                        self.logger.error(account_index,
                                          f"Прокси {proxy} не работает, пропускаем аккаунт {wallet.address}")
                        return

                    user_agent = self.ua_manager.get(wallet.address)
                    self.ua_manager.save(wallet.address, user_agent)

                    login_data = await client.login(user_agent)
                    if not login_data:
                        return

                    access_token = login_data["access_token"]
                    aa_address = login_data["aa_address"]
                    displayed_name = login_data["displayed_name"]
                    cookie_header = login_data["cookie_header"]

                    profile = await client.get_user_profile(access_token)
                    if not profile or not profile.get("profile"):
                        self.logger.error(account_index, "Не удалось получить профиль или профиль пуст")
                        return
                    self.logger.info(account_index,
                                     f"Пользователь: {profile['profile'].get('displayed_name', displayed_name or 'Unknown')}")
                    self.logger.info(account_index,
                                     f"EOA Адрес: {profile['profile'].get('eoa_address', wallet.address)}")
                    self.logger.info(account_index,
                                     f"Смарт-аккаунт: {profile['profile'].get('smart_account_address', aa_address)}")
                    self.logger.info(account_index, f"Всего XP: {profile['profile'].get('total_xp_points', 0)}")
                    self.logger.info(account_index,
                                     f"Реферальный код: {profile['profile'].get('referral_code', 'None')}")
                    badges_count = len(profile['profile'].get('badges_minted', [])) if profile['profile'].get(
                        'badges_minted') is not None else 0
                    self.logger.info(account_index, f"Бейджи: {badges_count}")
                    self.logger.info(account_index,
                                     f"Twitter подключен: {'Yes' if profile['social_accounts'].get('twitter', {}).get('id') else 'No'}")

                    stake_info = await client.get_stake_info(access_token, cookie_header)
                    if stake_info:
                        self.logger.info(account_index, "----- Информация о стейкинге -----")
                        self.logger.info(account_index,
                                         f"Моя застейканная сумма: {stake_info['my_staked_amount']} токенов")
                        self.logger.info(account_index,
                                         f"Общая застейканная сумма: {stake_info['staked_amount']} токенов")
                        self.logger.info(account_index, f"Количество делегаторов: {stake_info['delegator_count']}")
                        self.logger.info(account_index, f"APR: {stake_info['apr']}%")
                        self.logger.info(account_index, "-----------------------------")

                    faucet_success = await client.claim_daily_faucet(access_token, cookie_header, self.state_manager)
                    if faucet_success:
                        await asyncio.sleep(random.uniform(15, 20))  # Пауза 15–20 секунд
                        await client.stake_token(access_token, cookie_header)

                    await client.claim_stake_rewards(access_token, cookie_header)

                    for agent in self.config.AGENTS:
                        interaction_count = random.randint(self.config.MIN_INTERACTIONS, self.config.MAX_INTERACTIONS)
                        self.logger.info(account_index,
                                         f"Количество взаимодействий с агентом {agent['name']}: {interaction_count}")
                        if agent["name"] == "Professor":
                            agent_header = "\n\n----- PROFESSOR -----"
                        elif agent["name"] == "Crypto Buddy":
                            agent_header = "\n----- CRYPTO BUDDY -----"
                        else:
                            agent_header = "\n----- SHERLOCK -----"
                        self.logger.agent(account_index, agent_header)
                        for i in range(interaction_count):
                            prompt = self.get_random_prompt(agent["name"], prompt_generators)
                            if not prompt:
                                self.logger.error(account_index, f"Не удалось выбрать промпт для {agent['name']}")
                                continue
                            await client.interact_with_agent(access_token, aa_address, cookie_header, agent, prompt,
                                                             i + 1)
                            await asyncio.sleep(3)
                        self.logger.agent(account_index, "\n")

                    # Выполнение квиза
                    quiz_id = await client.create_quiz(access_token, cookie_header, self.state_manager)
                    if quiz_id:
                        quiz_data = await client.get_quiz(quiz_id, access_token, cookie_header)
                        if quiz_data:
                            await client.submit_quiz_answer(
                                quiz_data["quiz_id"],
                                quiz_data["question_id"],
                                quiz_data["answer"],
                                access_token,
                                cookie_header
                            )

            except Exception as e:
                self.logger.error(account_index, f"Ошибка обработки аккаунта {account['private_key'][:10]}...: {e}")

    async def run(self):
        self.logger.banner()
        prompt_generators = await self.load_prompts()
        accounts = self.account_manager.load_accounts(self.logger)
        proxies = self.account_manager.load_proxies(self.logger)
        if not accounts:
            self.logger.error(0, "Нет валидных приватных ключей в accounts.txt")
            return
        if not proxies:
            self.logger.error(0, "Нет прокси в proxies.txt")
            return

        semaphore = asyncio.Semaphore(self.config.MAX_WORKERS)
        tasks = []
        for index, account in enumerate(accounts, 1):
            proxy = proxies[(index - 1) % len(proxies)]
            tasks.append(self.process_account(index, account, proxy, prompt_generators, semaphore))

        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.success(0, "Выполнение бота завершено")


if __name__ == "__main__":
    import platform

    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    bot = KiteAIBot()
    asyncio.run(bot.run())
