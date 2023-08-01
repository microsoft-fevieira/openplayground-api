import requests, json, re, warnings, random

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"

class Model:
  def __init__(self, data):
    self.provider = data.get("provider")
    self.name = data.get("name")
    self.version = data.get("version")
    self.params = data.get("parameters")
    self.capabilities = data.get("capabilities")
    self.tag = f"{self.provider.strip()}:{self.name.strip()}"
  
  def resolve_params(self, kwargs):
    final_params = {}
    for param_name in self.params:
      if param_name in kwargs:
        final_params[param_name] = kwargs[param_name]
      else:
        final_params[param_name] = self.params[param_name]["value"]

    return final_params

class Client:
  api_url = "https://nat.dev/api"

  def __init__(self, token, email=""):
    self.email = email
    self.token = token

    self.session = requests.Session()
    self.headers = {
      "User-Agent": user_agent,
      "Referrer": "https://nat.dev/",
      "Host": "nat.dev",
      # "Authorization": f"Bearer {token}"
    }
    self.session.headers.update(self.headers)

    cookies = {
        "__client_uat": '1687331383',
        "__session": 'eyJhbGciOiJSUzI1NiIsImtpZCI6Imluc18yTWtjQlhndjhpbEwxcGNDTnB3MXV5anF0azgiLCJ0eXAiOiJKV1QifQ.eyJhenAiOiJodHRwczovL25hdC5kZXYiLCJleHAiOjE2OTA4MjI2MzQsImlhdCI6MTY5MDgyMjU3NCwiaXNzIjoiaHR0cHM6Ly9jbGVyay5uYXQuZGV2IiwianRpIjoiODE5NGY1ODBlOTE1ZDBlYWRkYTUiLCJuYmYiOjE2OTA4MjI1NjQsInNpZCI6InNlc3NfMlRMTmxtOVA3VmxaWkRMQ2IzUG1sRXR5WVFjIiwic3ViIjoidXNlcl8yT0lvWGpMbWFGNjR3Ujg2V3E0NnZmQkVBRWoiLCJ1c2VyX2VtYWlsIjoiY29nbWFwczAwQGdtYWlsLmNvbSIsInVzZXJfZmlyc3RfbmFtZSI6IlJlc2VhcmNoIiwidXNlcl9pZCI6InVzZXJfMk9Jb1hqTG1hRjY0d1I4NldxNDZ2ZkJFQUVqIiwidXNlcl9sYXN0X25hbWUiOiJDb2dNYXBzIn0.W7Y3rEfqtRAJh9R22beydCutsqYxy164Ttvmi2ehj7TsMsryXaLy1FuDm_nmV5mT1KDLVqKaFVHdxduB5HLFGmZ004KbxKrxzhARJVO3Pxlla2uYy-C8EUU4krE6TEMXOneNbBmab-7lSDt9dkUen8e1UphIU0QpSgZBdLQawtYbZ-me9fF_bvgpLCJu0seRfAGyMXN5wNEXF1s69kz4qHmdMS6NSO2gNcyMHyFEe59T81YywZXgXsoHVKhkiG7AQgnI8kVf-fITUA5TXOKI7T3t7SbDQBOfyIyeP6xctYvytr2aioqAqwK29HIUXjgjplMYGQDLQ89ZbItHgzpReA',
        "__client": 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNsaWVudF8yUlZOZENTVzB1YnJEdGQyc1ZvSGphUmRoSGYiLCJyb3RhdGluZ190b2tlbiI6InQzYWtnYWx0aHhlczljN3V5Z2dwZWdhZjAzdmY1cHljOXA3djV1bWgifQ.KkRrMdjNtn-oBGvtZBJ7g3XKnFD-Z99W1_qlU9jftYy2kqP6nd__7KqFGSR9QYQq7fv5vGCSx3icK_2bzccSkCir__XBQFSD74FqKojdXDgG9g1KHzqIC-BjnEQa-OZNTBHE_z4ZzbLArKGhXlixws1MK-6rz2eE3aZFQcxfllG5gfYbtcWom-skD797WmD-hklM_8cSYSSjEFelIem_Bs6hnYHJ-sokoE0N0PIti-p_xHcYAFC5fE6oSpsqvSoJ1AA6ZQXlC3_04GGIN3kw66nZ315dVXylW6WLsBCFMf1DoOHdJSQ7eoijzbd-x43d2Ko1TyEI8RHYwFqalMTJLA',
        "__cf_bm": 'rJXVI3_jozN503Eo5etmwNQLk5PBb.9qxsw8HtWmkQ0-1690822242-0-AaRlmt1QQBlXarRSx6D7tRFx5BHFAZNfnKdRwKK6FIy7n2IG4JBLLL9Bxpo5Upyg72trAHbmzUn+aQqAUGfcxoY=',
        "_cfuvid": 'EoovBLB.NCSYtIdjLRw9qhlpW8LkOlcja1817kn0FRg-1690818541797-0-604800000',
        "ph_phc_U9MeYtLOvAD6HTT3IRczbNnVKBNRFXSyJ0wodxFGJRu_posthog": r"%7B%22distinct_id%22%3A%220189aca3-762d-7f9e-814b-f088136b3203%22%2C%22%24device_id%22%3A%220189aca3-762d-7f9e-814b-f088136b3203%22%2C%22%24user_state%22%3A%22anonymous%22%2C%22%24sesid%22%3A%5B1690822473463%2C%220189accf-0b9f-7dcf-9924-f0c2df871875%22%2C1690821397407%5D%2C%22%24session_recording_enabled_server_side%22%3Afalse%2C%22%24autocapture_disabled_server_side%22%3Afalse%2C%22%24active_feature_flags%22%3A%5B%5D%2C%22%24enabled_feature_flags%22%3A%7B%7D%2C%22%24feature_flag_payloads%22%3A%7B%7D%7D"
    }

    self.cookie_jar = requests.cookies.RequestsCookieJar()

    for cookie in cookies:
      self.session.cookies.set(cookie, cookies[cookie])
      self.cookie_jar.set(cookie, cookies[cookie])

    self.models = self.get_models()
  
  def get_xsession(self, data):
    data_bytes = json.dumps(data).encode()
    salt = get_random_bytes(16)
    iv = get_random_bytes(12)

    aes_key = PBKDF2(self.email.encode(), salt, 32, count=10000, hmac_hash_module=SHA256)
    cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    encrypted_data, tag = cipher.encrypt_and_digest(data_bytes)
    return f"{encrypted_data.hex()}:{salt.hex()}:{iv.hex()}:{tag.hex()}"
  
  def get_models(self):
    models_url = self.api_url + "/models-enabled"
    r = self.session.get(models_url)
    r = requests.request('GET', models_url, cookies=self.cookie_jar)
    data = r.json()

    models = {}
    for key in data:
      model = Model(data[key])
      models[key] = model

    return models
  
  def generate(self, model, prompt, **kwargs):
    if not isinstance(model, Model):
      model = self.models[model]

    generation_url = self.api_url + "/inference/text"
    xsession_data = {
      "navigator": {
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "language": "en-US",
        "platform": "Linux x86_64",
        "vendor": "",
        "hardwareConcurrency": 2
      },
      "prompt": prompt,
      "p": random.randint(0, 100),
      "q": random.randint(0, 100),
      "mode": 1
    }
    headers = {
        'authority': 'nat.dev',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'text/plain;charset=UTF-8',
        # 'cookie': '__client_uat=1690818553; __session=eyJhbGciOiJSUzI1NiIsImtpZCI6Imluc18yTWtjQlhndjhpbEwxcGNDTnB3MXV5anF0azgiLCJ0eXAiOiJKV1QifQ.eyJhenAiOiJodHRwczovL25hdC5kZXYiLCJleHAiOjE2OTA4NTc0OTcsImlhdCI6MTY5MDg1NzQzNywiaXNzIjoiaHR0cHM6Ly9jbGVyay5uYXQuZGV2IiwianRpIjoiOGJiMThjZGRkYmIwNjhjYjkxYTgiLCJuYmYiOjE2OTA4NTc0MjcsInNpZCI6InNlc3NfMlRMTmxtOVA3VmxaWkRMQ2IzUG1sRXR5WVFjIiwic3ViIjoidXNlcl8yT0lvWGpMbWFGNjR3Ujg2V3E0NnZmQkVBRWoiLCJ1c2VyX2VtYWlsIjoiY29nbWFwczAwQGdtYWlsLmNvbSIsInVzZXJfZmlyc3RfbmFtZSI6IlJlc2VhcmNoIiwidXNlcl9pZCI6InVzZXJfMk9Jb1hqTG1hRjY0d1I4NldxNDZ2ZkJFQUVqIiwidXNlcl9sYXN0X25hbWUiOiJDb2dNYXBzIn0.ImmkMjDh-cjCIMujOIOTtYF4F4AWIms_rDGi9IBXEmA15qxj5Lcp9OA7MgNKXZB6eJ154I9cOOvHDGJwsiYVWVl1ijWFuMy7p5EXirQfXZ0deGg9cyhjzvsUJGABR93yGu277wRDyNlI4E-d6PWYHQmHB79ksrwTI1T-v6Y7uAfWfO5XbZ8Y21lWwxG7LP9uhVMDI-0RML7HlfbDwHw2raX_G8j7Tkytl6ddMDT3uydvsHvT-ZtnY9xtoUz8tHls8dxUY-Fa1jOPdiNEtz2JzX_FDEQUdlRh0QcLWwiIivWKI6sauWwky3o1KhBMP2zgKUEOGsH_-MglicvPTLPr8A; ph_phc_U9MeYtLOvAD6HTT3IRczbNnVKBNRFXSyJ0wodxFGJRu_posthog=%7B%22distinct_id%22%3A%220189aca3-762d-7f9e-814b-f088136b3203%22%2C%22%24device_id%22%3A%220189aca3-762d-7f9e-814b-f088136b3203%22%2C%22%24user_state%22%3A%22anonymous%22%2C%22%24sesid%22%3A%5B1690857474144%2C%220189aec5-2bf1-746d-98d0-e2a765f1ab74%22%2C1690854304577%5D%2C%22%24session_recording_enabled_server_side%22%3Atrue%2C%22%24autocapture_disabled_server_side%22%3Afalse%2C%22%24active_feature_flags%22%3A%5B%5D%2C%22%24enabled_feature_flags%22%3A%7B%7D%2C%22%24feature_flag_payloads%22%3A%7B%7D%2C%22%24console_log_recording_enabled_server_side%22%3Atrue%2C%22%24session_recording_recorder_version_server_side%22%3A%22v2%22%7D',
        'origin': 'https://nat.dev',
        'referer': 'https://nat.dev/',
        'sec-ch-ua': '"Not/A)Brand";v="99", "Microsoft Edge";v="115", "Chromium";v="115"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188',
    }
    cookies = {
        '__client_uat': '1690818553',
        '__session': 'eyJhbGciOiJSUzI1NiIsImtpZCI6Imluc18yTWtjQlhndjhpbEwxcGNDTnB3MXV5anF0azgiLCJ0eXAiOiJKV1QifQ.eyJhenAiOiJodHRwczovL25hdC5kZXYiLCJleHAiOjE2OTA4NTc0OTcsImlhdCI6MTY5MDg1NzQzNywiaXNzIjoiaHR0cHM6Ly9jbGVyay5uYXQuZGV2IiwianRpIjoiOGJiMThjZGRkYmIwNjhjYjkxYTgiLCJuYmYiOjE2OTA4NTc0MjcsInNpZCI6InNlc3NfMlRMTmxtOVA3VmxaWkRMQ2IzUG1sRXR5WVFjIiwic3ViIjoidXNlcl8yT0lvWGpMbWFGNjR3Ujg2V3E0NnZmQkVBRWoiLCJ1c2VyX2VtYWlsIjoiY29nbWFwczAwQGdtYWlsLmNvbSIsInVzZXJfZmlyc3RfbmFtZSI6IlJlc2VhcmNoIiwidXNlcl9pZCI6InVzZXJfMk9Jb1hqTG1hRjY0d1I4NldxNDZ2ZkJFQUVqIiwidXNlcl9sYXN0X25hbWUiOiJDb2dNYXBzIn0.ImmkMjDh-cjCIMujOIOTtYF4F4AWIms_rDGi9IBXEmA15qxj5Lcp9OA7MgNKXZB6eJ154I9cOOvHDGJwsiYVWVl1ijWFuMy7p5EXirQfXZ0deGg9cyhjzvsUJGABR93yGu277wRDyNlI4E-d6PWYHQmHB79ksrwTI1T-v6Y7uAfWfO5XbZ8Y21lWwxG7LP9uhVMDI-0RML7HlfbDwHw2raX_G8j7Tkytl6ddMDT3uydvsHvT-ZtnY9xtoUz8tHls8dxUY-Fa1jOPdiNEtz2JzX_FDEQUdlRh0QcLWwiIivWKI6sauWwky3o1KhBMP2zgKUEOGsH_-MglicvPTLPr8A',
        'ph_phc_U9MeYtLOvAD6HTT3IRczbNnVKBNRFXSyJ0wodxFGJRu_posthog': '%7B%22distinct_id%22%3A%220189aca3-762d-7f9e-814b-f088136b3203%22%2C%22%24device_id%22%3A%220189aca3-762d-7f9e-814b-f088136b3203%22%2C%22%24user_state%22%3A%22anonymous%22%2C%22%24sesid%22%3A%5B1690857474144%2C%220189aec5-2bf1-746d-98d0-e2a765f1ab74%22%2C1690854304577%5D%2C%22%24session_recording_enabled_server_side%22%3Atrue%2C%22%24autocapture_disabled_server_side%22%3Afalse%2C%22%24active_feature_flags%22%3A%5B%5D%2C%22%24enabled_feature_flags%22%3A%7B%7D%2C%22%24feature_flag_payloads%22%3A%7B%7D%2C%22%24console_log_recording_enabled_server_side%22%3Atrue%2C%22%24session_recording_recorder_version_server_side%22%3A%22v2%22%7D',
    }
    payload = {
        "prompt": prompt,
        "models": [
            {
                "name": model.tag,
                "tag": model.tag,
                "capabilities": model.capabilities,
                "provider": model.provider,
                "parameters": model.resolve_params(kwargs),
                "enabled": True,
                "selected": True
            }
        ],
        "stream": True
    }
    # payload = '{"prompt":"You are an AI assistant that helps people find information. You will receive a task and think step by step. Then provide your final outcome following the regular expression \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'Answer: ([0-9]+,\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\s*)*[0-9]+\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\n\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\nImagine a building with six rooms. From the lobby you have two choices, you can go to room 1 or room 2. You enter room 1, at the other end of room 1 there\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'s a door that leads to room 3, and room 3 leads to room 5. There\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'s a chest in room 5. You open it and there\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'s 10 dollars, but you do not take any money, you\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'re just learning about the environment. Then you exit and start over. This time in the lobby you choose room 2, which has a door to room 4, and room 4 has a door that leads to room 6. You find a chest with 50 dollars in room 6, but you do not take any money, you\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'re just learning about the environment. You return to the lobby. You will only be able to choose one path that leads to the most money. Which room from the lobby will lead to the path where one can make the most money?The path which will lead to the most money is to choose room 1 from the lobby. From room 1 you can go to room 3, where there is a chest with 10 dollars. Then you can go to room 5 and get the chest with 10 dollars, resulting in a total of 20 dollars. If you choose to go to room 2 from the lobby, you will only be able to go to room 4 and room 6, which do not contain any money. Therefore, the path that will lead to the most money is to choose room 1 from the lobby.","models":[{"name":"replicate:replicate-llama/alpaca-7b","tag":"replicate:replicate-llama/alpaca-7b","capabilities":["logprobs","completion"],"provider":"replicate","parameters":{"temperature":0.01,"contextLength":768,"maximumLength":256,"topP":0.95,"repetitionPenalty":1,"stopSequences":[]},"enabled":true,"selected":true}],"stream":true}'
    payload = json.dumps(payload)
    # r = self.session.post(generation_url, json=payload, stream=True, headers=headers)
    r = requests.post('https://nat.dev/api/inference/text', cookies=cookies, headers=headers, data=payload)

    for chunk in r.iter_content(chunk_size=None):
      r.raise_for_status()
      
      chunk_str = chunk.decode()
      data_regex = r"event:(\S+)\sdata:(.+)\s"
      matches = re.findall(data_regex, chunk_str)
      for match in matches:
        data = json.loads(match[1])
        data["event"] = match[0]
        yield data

class Auth:
  api_url = "https://clerk.nat.dev/v1/client/sign_ins/"

  def __init__(self):
    self.session = requests.Session()
    self.headers = {
      "Host": "clerk.nat.dev",
      "User-Agent": user_agent,
      "Origin": "https://accounts.nat.dev"
    }
    self.session.params = {
      "_clerk_js_version": "4.32.6"
    }

    self.session.headers.update(self.headers)
  
  def check_errors(self, r):
    data = r.json()
    if r.status_code != 200:
      error_code = data["errors"][0]["code"]
      error_message = data["errors"][0]["long_message"]
      raise RuntimeError(f"{error_code}: {error_message}")
  
  #send verification email
  def send_otp_code(self, email_address):
    payload = {
      "identifier": email_address,
    }

    r = self.session.post(self.api_url, data=payload)
    data = r.json()
    self.check_errors(r)

    self.api_url_sia = data["response"]["id"]
    email_id = data["client"]['sign_in']['supported_first_factors'][0]['email_address_id']

    payload = {
      "email_address_id": email_id,
      "strategy": "email_code"
    }
    self.session.post(self.api_url + self.api_url_sia + "/prepare_first_factor", data=payload)
  
  #otp process
  def verify_otp_code(self, otp_code):
    payload = {
      "strategy": "email_code",
      "code": otp_code.strip()
    }
    r = self.session.post(self.api_url + self.api_url_sia + "/attempt_first_factor", data=payload)
    data = r.json()
    self.check_errors(r)

    if r.status_code != 200:
      print(r.text)

    token = data["client"]["sessions"][0]["last_active_token"]["jwt"]
    return token