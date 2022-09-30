import ldap3
import json
import logging

from ldap3 import ALL_ATTRIBUTES, Connection, NTLM, Server, MODIFY_REPLACE

LDAP_HOST = "tpedc03.wanhai.com"
DOMAIN = 'wanhai.com'
ad_server = Server(LDAP_HOST, port=3268, get_info=ldap3.ALL, connect_timeout=5)
LDAP_SERVER_POOL = [ad_server]
SERVER_USER = 'wanhai\op manager'
SERVER_PASSWORD = ""

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Main Logger')


class ActiveDirectory(object):

    def __init__(self):
        """
        initialize
        """
        self.conn = Connection(  # 配置服务器连接参数
            server=LDAP_SERVER_POOL,
            auto_bind=True,
            authentication=NTLM,  # it's require to connect Windows AD
            read_only=True,  # Not allow to modify：True
            user=SERVER_USER,  # Administrator account
            password=SERVER_PASSWORD, # Administrator password
        )

        self.active_base_dn = 'OU=it,OU=tpe,OU=tw,OU=MailAccount,DC=wanhai,DC=com'  #base dn
        self.search_filter = '(objectclass=user)'  #filter to search user
        self.ou_search_filter = '(objectclass=organizationalUnit)'  # filter to search OU

    def users_get(self):
        '''取得所有用戶'''
        self.conn.search(search_base=self.active_base_dn, search_filter=self.search_filter, attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)['entries']
        return res

    def OU_get(self):
        '''取得所有OU'''
        self.conn.search(search_base=self.active_base_dn, search_filter=self.ou_search_filter,
                         attributes=ALL_ATTRIBUTES)
        res = self.conn.response_to_json()
        res = json.loads(res)['entries']
        return res

    def create_obj(self, dn, type, attr=None):
        '''
        新建用戶or 部門，User需要設置密碼，激活賬戶
        :param dn: dn = "ou=人事部3,ou=羅輯實驗室,dc=adtest,dc=intra"  # 創建的OU的完整路徑
                   dn = "cn=張三,ou=人事部3,ou=羅輯實驗室,dc=adtest,dc=intra"  # 創建的User的完整路徑
        :param type:選項：ou or user
        :param attr = {#User 屬性表，需要設置什麽屬性，增加對應的鍵值對
                        "SamAccountName": "zhangsan",  # 賬號
                        "EmployeeID":"1",    # 員工編號
                        "Sn": "張",  # 姓
                        "name": "張三",
                        "telephoneNumber": "12345678933",
                        "mobile": "12345678933",
                        "UserPrincipalName":"zhangsan@adtest.com",
                        "Mail":"zhangsan@adtest.com",
                        "Displayname": "張三",
                        "Manager":"CN=李四,OU=人事部,DC=adtest,DC=com",#需要使用用戶的DN路徑
                    }
                attr = {#OU屬性表
                        'name':'人事部',
                        'managedBy':"CN=張三,OU=IT組,OU=羅輯實驗室,DC=adtest,DC=intra", #部分負責人
                        }
        :return:True and success 是建立成功
        (True, {'result': 0, 'description': 'success', 'dn': '', 'message': '', 'referrals': None, 'type': 'addResponse'})

        '''
        object_class = {'user': ['user', 'posixGroup', 'top'],
                        'ou': ['organizationalUnit', 'posixGroup', 'top'],
                        }
        res = self.conn.add(dn=dn, object_class=object_class[type], attributes=attr)
        if type == "user":  # 如果是用户时，我们需要给账户设置密码，并把账户激活
            self.conn.extend.microsoft.modify_password(dn, "XXXXXXXXX")  # 设置用户密码
            self.conn.modify(dn, {'userAccountControl': [('MODIFY_REPLACE', 512)]})  # 激活用户
        return res, self.conn.result

    def del_obj(self, DN):
        '''
        删除用户 or 部门
        :param DN:
        :return:True
        '''
        res = self.conn.delete(dn=DN)
        return res

    def update_obj(self, dn, attr):
        '''更新員工 or 部門屬性
        先比較每個屬性值，是否和AD中的屬性一致，不一樣的記錄，統一update
        注意：
            1. attr中dn屬性寫在最後
            2. 如果name屬性不一樣的話，需要先變更名字（實際是變更原始dn為新name的DN），後續繼續操作update and move_object
        User 的 attr 照如下格式寫：
        dn = "cn=test4,ou=IT組,dc=adtest,dc=com" #需要移動的User的原始路徑
        {#updateUser需要更新的屬性表
             "Sn": "李",  # 姓
             "telephoneNumber": "12345678944",
             "mobile": "12345678944",
             "Displayname": "張三3",
             "Manager":"CN=李四,OU=人事部,DC=adtest,DC=com",#需要使用用戶的DN路徑
             'DistinguishedName':"cn=張三,ou=IT組,dc=adtest,dc=com" #用戶需要移動部門時，提供此屬性，否則不提供
            }

        OU 的 attr 格式如下：
        dn = "ou=人事部,dc=adtest,dc=com" #更新前OU的原始路徑
        attr = {
        'name':'人事部',
        'managedBy':"CN=張三,OU=IT組,DC=adtest,DC=com",
        'DistinguishedName': "ou=人事部,dc=adtest,dc=com" # 更新後的部門完整路徑
        }
        '''
        changes_dic = {}
        for k, v in attr.items():
            if not self.conn.compare(dn=dn, attribute=k, value=v):
                if k == "name":
                    res = self.__rename_obj(dn=dn, newname=attr['name'])  # 改过名字后，DN就变了,这里调用重命名的方法
                    if res['description'] == "success":
                        if "CN" == dn[:2]:
                            dn = "cn=%s,%s" % (attr["name"], dn.split(",", 1)[1])
                        if "OU" == dn[:2]:
                            dn = "DN=%s,%s" % (attr["name"], dn.split(",", 1)[1])
                if k == "DistinguishedName":  # 如果属性里有“DistinguishedName”，表示需要移动User or OU
                    self.__move_object(dn=dn, new_dn=v)  # 调用移动User or OU 的方法
                changes_dic.update({k: [(MODIFY_REPLACE, [v])]})
                self.conn.modify(dn=dn, changes=changes_dic)
        return self.conn.result

    def __rename_obj(self, dn, newname):
        '''
        OU or User 重命名方法
        :param dn:需要修改的object的完整dn路徑
        :param newname: 新的名字，User格式："cn=新名字";OU格式："OU=新名字"
        :return:返回中有：'description': 'success', 表示操作成功
        {'result': 0, 'description': 'success', 'dn': '', 'message': '', 'referrals': None, 'type': 'modDNResponse'}
        '''
        self.conn.modify_dn(dn, newname)
        return self.conn.result

    def compare_attr(self, dn, attr, value):
        '''比較員工的某個屬性
        '''
        res = self.conn.compare(dn=dn, attribute=attr, value=value)
        return res

    def __move_object(self, dn, new_dn):
        '''移動員工 ot 部門到新部門'''
        relative_dn, superou = new_dn.split(",", 1)
        res = self.conn.modify_dn(dn=dn, relative_dn=relative_dn, new_superior=superou)
        return res

    def check_credentials(self, username, password):
        """
        驗證user帳密
        """
        ldap_user = ('\\{}@' + DOMAIN).format(username)
        server = Server(LDAP_HOST)

        connection = Connection(server, user=ldap_user, password=password, authentication=NTLM)
        try:
            logger.info("username:%s ;res: %s" % (username, connection.bind()))
            return connection.bind()
        except:
            logger.warning("username:%s ;res: %s" % (username, connection.bind()))
            return False
        finally:
            connection.closed
