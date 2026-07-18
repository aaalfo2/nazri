import requests
import yaml
import html
import urllib.parse
import hashlib


SOURCE = (
    "https://raw.githubusercontent.com/"
    "ebrasha/free-v2ray-public-list/"
    "refs/heads/main/separated-protocols/"
    "hysteria2_configs.txt"
)

OUTPUT = "config.yaml"


def download_source():
    r = requests.get(
        SOURCE,
        timeout=30
    )

    r.raise_for_status()

    return html.unescape(r.text)



def parse_node(line):

    if not line.startswith("hysteria2://"):
        return None


    try:

        line = html.unescape(line.strip())


        # Remove comments
        if "#" in line:
            url, remark = line.split("#", 1)
        else:
            url = line
            remark = ""


        if "undefined" in url:
            return None


        parsed = urllib.parse.urlparse(url)


        server = parsed.hostname
        port = parsed.port
        password = parsed.username


        if not server:
            return None


        if not port:
            return None


        if not password:
            return None



        query = urllib.parse.parse_qs(
            parsed.query,
            keep_blank_values=True
        )


        # Unique name
        uid = hashlib.md5(
            url.encode("utf-8")
        ).hexdigest()[:8]


        name = (
            f"{server}:{port}-{uid}"
        )


        proxy = {

            "name": name,

            "type": "hysteria2",

            "server": server,

            "port": port,

            "password": password

        }



        # SNI

        if "sni" in query:

            proxy["sni"] = (
                query["sni"][0]
            )



        # Certificate checking

        insecure = (

            query.get("insecure")
            == ["1"]

            or

            query.get("allowInsecure")
            == ["1"]

        )


        if insecure:

            proxy["skip-cert-verify"] = True



        # Obfuscation

        if "obfs" in query:


            obfs_type = query["obfs"][0]


            # salamander requires password

            if (
                obfs_type == "salamander"
                and
                "obfs-password" not in query
            ):
                return None



            proxy["obfs"] = obfs_type



            if "obfs-password" in query:

                proxy["obfs-password"] = (
                    query["obfs-password"][0]
                )



        return proxy



    except Exception:

        return None




def proxy_fingerprint(proxy):

    data = "|".join(
        [
            str(proxy.get("server")),
            str(proxy.get("port")),
            str(proxy.get("password")),
            str(proxy.get("sni")),
            str(proxy.get("obfs")),
            str(proxy.get("obfs-password"))
        ]
    )


    return hashlib.md5(
        data.encode("utf-8")
    ).hexdigest()



def valid_proxy(proxy):

    if not proxy.get("server"):
        return False


    if not proxy.get("port"):
        return False


    if not proxy.get("password"):
        return False


    if (
        proxy.get("obfs")
        and
        not proxy.get("obfs-password")
    ):
        return False


    return True




def main():

    text = download_source()


    proxies = []

    seen = set()



    for line in text.splitlines():

        proxy = parse_node(line)


        if not proxy:
            continue


        if not valid_proxy(proxy):
            continue



        fp = proxy_fingerprint(proxy)


        if fp in seen:
            continue


        seen.add(fp)


        proxies.append(proxy)



    print(
        f"Generated {len(proxies)} proxies"
    )



    names = [
        p["name"]
        for p in proxies
    ]



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

                "proxies": names,

                "url":
                "https://www.gstatic.com/generate_204",

                "interval": 300,

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
        encoding="utf-8"
    ) as f:


        yaml.safe_dump(
            config,
            f,
            allow_unicode=True,
            sort_keys=False
        )



if __name__ == "__main__":
    main()
