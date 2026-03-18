#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : github@wd210010 https://github.com/wd210010/just_for_happy
# @Time : 2026/3/18
# -------------------------------
# cron "30 5 * * *" script-path=xxx.py,tag=匹配cron用
# const $ = new Env('DuckCoding签到')

import sys
import os
import requests
import notify


# export duckcoding_session='session值&用户ID'      多号#号隔开
# 用户ID：登录后个人中心页面显示「ID: xxxxx」，或浏览器控制台执行 JSON.parse(localStorage.user).id

BASE_URL = "https://www.duckcoding.ai"
CHECKIN_URL = f"{BASE_URL}/api/user/checkin"


def main():
    r = 1
    accounts = ql_env()
    print("共找到" + str(len(accounts)) + "个账号")
    for acc in accounts:
        print("------------正在执行第" + str(r) + "个账号----------------")
        sign_in(acc.strip())
        r += 1


def sign_in(account):
    """account 格式: session&user_id"""
    try:
        parts = account.split("&", 1)
        if len(parts) < 2:
            raise ValueError(
                "格式需为 session&用户ID。用户ID获取：个人中心页面「ID: xxxxx」，"
                "或控制台执行 JSON.parse(localStorage.user).id"
            )
        session, user_id = parts[0].strip(), parts[1].strip()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": f"{BASE_URL}/console/personal",
            "New-Api-User": user_id,
        }
        cookies = {"session": session}
        resp = requests.post(CHECKIN_URL, headers=headers, cookies=cookies, timeout=15)
        data = resp.json()

        if data.get("success"):
            msg = data.get("message", "签到成功")
            quota = data.get("data", {}).get("quota_awarded")
            if quota is not None:
                msg = f"{msg}，获得额度 {quota}"
            print(msg)
            notify.send("DuckCoding签到", msg)
        else:
            msg = data.get("message", "签到失败")
            print(msg)
            notify.send("DuckCoding签到", msg)
    except Exception as e:
        err = f"签到异常: {e}"
        print(err)
        notify.send("DuckCoding签到", err)


def ql_env():
    env_key = "duckcoding_session"
    if env_key in os.environ:
        token_list = os.environ[env_key].split("#")
        if token_list:
            return token_list
        print(f"{env_key}变量未启用")
        sys.exit(1)
    print(f"未添加{env_key}变量")
    sys.exit(0)


if __name__ == "__main__":
    main()
