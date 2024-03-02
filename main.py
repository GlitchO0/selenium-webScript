from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.action_chains import ActionChains
from time import sleep
import json
import os
import shutil
from licensing.models import *
from licensing.methods import Key, Helpers
from twocaptcha import TwoCaptcha
from urllib.parse import urlparse



RSAPubKey = "<RSAKeyValue><Modulus>1nxvBTLNZWiJSOgO7oXwP/GEZeZNIh9p756rmYPK72fcpEFJ3oBvZQMWHOMpqFRPrtT6EL5cw3r5vOc/nmrcpBrWGrhJfIfjQCRonP4XHakQvZAwzOK9gJU/AdRt0i1wks1eHkQIwtRTpki6/URJK4r9irKV7tu5Z7L6eAS903M5XmW57hZWDhNJtObCErBPcxG1Gig/8I+rnPIJCy/33mhp2c5GqD4PWodV8uuhiKYs9N6eDAorOLPdk0oWPEMd6OceYyINEYEhbvfPWGaMz3sWpum4XLdeg/l9K7TwQPNhpuC9J99eahGWUc9S8JjlB36HyE3rQof2gKn/7kP7Sw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
auth = "WyI2NDQ2OTQ2NyIsIjIzdU52dTRBcWdUZ1B5THBNeVhkem5nNGdEblRzdTh0djlYYUFSSDciXQ=="
driver = None

def AuthKey():
    key = read_license_key()
    result = Key.activate(
        token=auth,\
        rsa_pub_key=RSAPubKey,\
        product_id=22335,\
        key=key,\
        machine_code=Helpers.GetMachineCode()
    )

    if result[0] == None or not Helpers.IsOnRightMachine(result[0]):
        # an error occurred or the key is invalid or it cannot be activated
        # (eg. the limit of activated devices was achieved)
        print("The license does not work: {0}".format(result[1]))
        exit()
    else:
        # everything went fine if we are here!
        print("The license is valid!")
        main()


# Function to initialize a WebDriver
def initialize_driver():
    print('Starting..')
    global driver
    chrome_driver_path = "chromedrive\chromedriver-win64\chromedriver.exe"
    chrome_service = ChromeService(executable_path=chrome_driver_path)
    chrome_options = webdriver.ChromeOptions()
    #chrome_options.add_argument("--load-extension=extensions/nopcha_new")
    chrome_options.add_argument("--incognito")
    # chrome_options.add_argument("--load-extension=2CaptchaMod")
    driver = webdriver.Chrome(service = chrome_service, options = chrome_options)
    

    positions = get_positions()
    first_position = positions.pop(0)
    positions.append(first_position)
    driver.set_window_position(first_position['x'], first_position['y'])
    update_positions(positions)
    driver.set_window_position(0, 0)
    driver.set_window_size(200, 400)

# Function to close the current WebDriver and open a new one
def close_and_open_driver():
    print('Closing browser and open new one..')
    global driver
    driver.delete_all_cookies()
    driver.quit()  # Close the current WebDriver
    initialize_driver()  # Initialize a new WebDriver

# Function to login in riot

def riot_login(email, password):
    driver.execute_script("window.open('about:blank', '_blank');")
    print(email, ":", password," ！#")
    driver.switch_to.window(driver.window_handles[1])
    driver.get("https://gaming.amazon.com/oauth/start/riot?overwrite=true&redirectUrl=https://gaming.amazon.com/loot/leagueoflegends")
    try:
        WebDriverWait(driver, 5).until(EC.presence_of_all_elements_located((By.LINK_TEXT, 'NOT YOU? SWITCH ACCOUNTS'))).click()
    except:
        pass
    driver.refresh()
    WebDriverWait(driver, 60).until(EC.presence_of_element_located((By.NAME, "username"))).send_keys(email)
    print('Signing in...')
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "password"))).send_keys(password)
    scroll_pixels = 500  # Change this value as needed
    driver.execute_script(f"window.scrollBy(0, {scroll_pixels});")
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, '//*[@id="root"]/div/main/div/form/div/div/div[2]/button'))).click()

def read_cookies():
    with open('cookies/cookies.txt', 'r') as file:
        cookies = file.read().splitlines()
    return cookies

def read_accounts():
    accounts = []
    with open("accounts.txt", 'r') as account:
        for line in account:
            email, password = line.strip().split(':')
            accounts.append((email, password))
    return accounts

def open_capsule_tab():
    driver.switch_to.window(driver.window_handles[0])

def open_riot_tab():
    driver.switch_to.window(driver.window_handles[0])

def remove_account_and_save_in_new_file(email, password):
    input_file_path = "accounts.txt"
    claimed_file_path = "already_claimed_accounts.txt"

    updated_accounts = []
    with open(input_file_path, 'r') as input_file:
        lines = input_file.readlines()

    claimed_account = f'{email}:{password}\n'

    with open(claimed_file_path, 'a') as claimed_file:
            claimed_file.write(claimed_account)

    for line in lines:
        if line.strip() != claimed_account.strip():
            updated_accounts.append(line)

    with open(input_file_path, 'w') as input_file:
        input_file.writelines(updated_accounts)

def save_not_signed_cookie(cookie):
    try:
        with open("cookies/not_signed_in_cookies.txt", "a") as file:
            file.write(cookie + "\n")
        print(f"Not signed cookies saved successfully.")
    except Exception as e:
        print(f"An error occurred while saving the not signed cookie")

def update_cookies_file(cookies, cookie_to_remove, file):
    with open(file, 'a') as needed_file:
        needed_file.write(cookie_to_remove + '\n')

    cookies.remove(cookie_to_remove)

    with open('cookies/cookies.txt', 'w') as file:
        file.write('\n'.join(cookies))

def is_auth_link(link):
    expected_domain = 'auth.riotgames.com'
    parsed_url = urlparse(link)
    return parsed_url.netloc == expected_domain

def make_sure_captcha_solved(email, password):
    sign_btn = False
    print('Solving Captcha..')
    start_time = time.time()
    while True:
        try:
            WebDriverWait(driver, 3).until(EC.element_to_be_clickable((By.XPATH, '//*[@id="root"]/div/main/div/form/div/div/div[2]/button')))
            sign_btn = True
        except:
            pass
        #if signed in success break the loop and continue
        if "gaming.amazon.com/" in driver.current_url or is_auth_link(driver.current_url):
            green_color = "\033[32m"
            reset_color = "\033[0m"
            print(f"{green_color}Captcha Bypassed..{reset_color}")
            break
        
def read_license_key():
    print('Reading license key..')
    license_key = None
    try:
        with open("key_file.txt", 'r') as file:
            license_key = file.readline().strip()
    except FileNotFoundError:
        print("License key file not found.")
    return license_key

# Function to get positions from the file
def get_positions():
    with open("positions.json", "r") as file:
        return json.load(file)

# Function to update and save positions to the file
def update_positions(positions):
    with open("positions.json", "w") as f:
        json.dump(positions, f)

def main():
    initialize_driver()

    #read the cookies files
    cookies = read_cookies()

    for cookie in cookies[:]:

        accounts = read_accounts()

        xmain = {
            'name': 'x-main',
            'value': cookie,
        }
        driver.get("https://gaming.amazon.com/prime-gaming-capsule-jan-24/dp/amzn1.pg.item.95eb1f68-2a19-45cb-a0ed-48d9b51b1781?ingress=amzn")


        driver.add_cookie(xmain)
        driver.refresh()
        try:
            WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.CLASS_NAME, 'sign-in-button')))
            print('Error in adding cookies..')
            save_not_signed_cookie(cookie)
            close_and_open_driver()
            continue
        except:
            print('Cookies added successfully..')

        for email, password in accounts[:]:
            riot_login(email, password)
            make_sure_captcha_solved(email, password)
            try:
                WebDriverWait(driver, 1000).until(EC.presence_of_element_located((By.XPATH, '//h1[contains(text(), "League of Legends")]')))
                print('Account Logged in successfully..')
                try:
                    WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.CSS_SELECTOR, 'div[data-a-target="AccountLinkStatus"]')))
                    print('Account is prime')
                    try:
                        open_capsule_tab()
                        print('Check if cookie is collected or no..')
                        driver.refresh()
                        get_in_game_content = WebDriverWait(driver, 3).until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'button[data-a-target="buy-box_call-to-action"]')))
                        print('Cookie is not collected..')
                        try:
                            open_riot_tab()
                            WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.XPATH, '//p[contains(text(), "Collected")]')))
                            print('Email is collected')
                            print('Remove email and save it in file...')
                            remove_account_and_save_in_new_file(email, password)
                            print('Done...')
                            driver.close()
                            open_capsule_tab()
                            continue

                        except:
                            print('Email not collected..')
                            print('Lets claim the capsule..')
                            open_capsule_tab()
                            get_in_game_content.click()
                            try:
                                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, '//h1[contains(text(), "Success, your Prime Gaming Capsule will be sent to your game")]')))
                                print('Capsule claimed successfully')
                                update_cookies_file(cookies, cookie, "cookies/done_cookies.txt")
                                remove_account_and_save_in_new_file(email, password)
                                close_and_open_driver()
                                break
                            except:
                                print('There was a problem in claim the capsule')

                    except:
                        print('Cookie is collected..')
                        update_cookies_file(cookies, cookie, "cookies/collected_cookies.txt")
                        print('Cookies removed and saved in folder..')
                        try:
                            open_riot_tab()
                            WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.XPATH, '//p[contains(text(), "Collected")]')))
                            print('Email is collected')
                            #print('Lets remove email and save it in new file...')
                            #remove_account_and_save_in_new_file(email, password)
                            #print('Done...')
                            close_and_open_driver()
                            break
                        except:
                            print('Email not collected..')
                            print('Change Cookies..')
                            close_and_open_driver()
                            break

                except:
                    print('Account is not prime')
                    update_cookies_file(cookies, cookie, "cookies/try_prime_cookies.txt")
                    print('Cookies removed and saved in folder..')
                    close_and_open_driver()
                    break
            except:
                print("There is a problem in sign in")
                break

main()