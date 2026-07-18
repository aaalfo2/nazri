import requests
import yaml
import html
import urllib.parse
import hashlib
import re


SOURCE = (
    "https://raw.githubusercontent.com/"
    "ebrasha/free-v2ray-public-list/"
    "refs/heads/main/separated-protocols/hysteria2_configs.txt"
)


OUTPUT = "config.yaml"


def download():

    r = requests.get(
        SOURCE,
        timeout=20
    )

    r.raise_for_status()

    return html.unescape(r.text)



def parse_node(line):

    if not line.startswith("hysteria2://"):
        return None

    try:

        line = html.unescape(line.strip())

        if "#" in line:
            url, remark = line.split("#", 1)
        else:
            url = line
            remark = ""

        if "undefined" in url:
            return None

        parsed = urllib.parse.urlparse(url)

        if not parsed.hostname or not parsed.username:
            return None


        query = urllib.parse.parse_qs(parsed.query)


        server = parsed.hostname
        port = parsed.port
        password = parsed.username


        unique_id = hashlib.md5(
            url.encode()
        ).hexdigest()[:6]


        proxy = {

            "name":
                f"{server}:{port}-{unique_id}",

            "type":
                "hysteria2",

            "server":
                server,

            "port":
                port,

            "password":
                password

        }


        if "sni" in query:
            proxy["sni"] = query["sni"][0]


        if (
            query.get("insecure") == ["1"]
            or query.get("allowInsecure") == ["1"]
        ):
            proxy["skip-cert-verify"] = True


        if "obfs" in query:
            proxy["obfs"] = query["obfs"][0]


        if "obfs-password" in query:
            proxy["obfs-password"] = (
                query["obfs-password"][0]
            )


        return proxy


    except Exception:
        return None



def fingerprint(proxy):

    raw = str(proxy)

    return hashlib.md5(
        raw.encode()
    ).hexdigest()



def main():

    text = download()


    proxies = []

    seen = set()


    for line in text.splitlines():

        node = parse_node(line)

        if not node:
            continue


        fp = fingerprint(node)


        if fp in seen:
            continue


        seen.add(fp)

        proxies.append(node)



    print(
        f"Generated {len(proxies)} nodes"
    )


    config = {


        "mixed-port": 7890,


        "allow-lan": True,


        "mode": "rule",


        "log-level": "info",


        "proxies": proxies,


        "proxy-groups": [

            {

                "name": "AUTO",

                "type": "url-test",

                "proxies": [
                    p["name"]
                    for p in proxies
                ],

                "url":
                "https://www.gstatic.com/generate_204",

                "interval": 180,

                "tolerance": 50

            },


            {

                "name": "PROXY",

                "type": "select",

                "proxies": [

                    "AUTO",

                    "DIRECT"

                ]

            }

        ],


        "rules": [

            "MATCH,PROXY"

        ]

    }


    with open(
        OUTPUT,
        "w",
        encoding="utf8"
    ) as f:

        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False
        )



if __name__ == "__main__":
    main()
