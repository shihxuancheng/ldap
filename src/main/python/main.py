from ldap_tools.AD import ActiveDirectory
import json


def main():
    ad = ActiveDirectory()
    print(json.dumps(ad.OU_get(), indent=2))
    # ActiveDirectory.check_credentials('richard_shih', 'Whlm1933')


if __name__ == '__main__':
    main()
