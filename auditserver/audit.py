import re
import json










#大括号匹配函数=========================================================================以下
def braceMatch(lines): #输入一个contract所在的行，返回这个contract所占的行数
    leftCount = 0
    i = 0
    ever = False
    for i in range(0,len(lines)):
        line = lines[i]
        leftList  = re.findall('{',line)
        rightList = re.findall('}',line)
        leftCount += len(leftList)
        if leftCount>0:
            ever = True
        leftCount -= len(rightList)
        if leftCount <= 0 and ever:
            break

    return i


#完成需求2.1============================================================================以下
#lines表达的是每行代码的累加



def judge2_1(lines): #传入一个contract
    i = 0
    j = 0
    for i in range(0,len(lines)):
        if re.search('function',lines[i])!=None:
            lenOfFunction = braceMatch(lines[i:])
            for j in range(i,i+lenOfFunction):          #遍历contract中function每一行
                if re.search("owner * = *[\w0-9]|_owner *= *[\w0-9]|creator *= *[\w0-9]|_creator *= *[\w0-9]",lines[j],re.IGNORECASE):
                    if re.search('internal|private',lines[i].split(')',1)[-1])  == None:
                        yield j
    yield -1


def judge2_2(lines): #传入一个contract
    i = 0
    j = 0
    dangerous_call = "\. *call *\( *bytes4\(|\. *delegatecall *\( *bytes4\(|\. *callcode *\( *bytes4\(|\. *delegatecall *\( *msg\. *data *\)|\. *callcode *\( *msg\. *data *\)|\. *call *\( *msg\.data *\)|\. *call *\( *data *\)|\. *callcode *\( *data *\)|\. *delegatecall *\( *data *\)|\. *call *\( *byte *\)| *\. *callcode *\( *byte *\)|\. *delegatecall *\( *byte *\) *"

    for i in range(0,len(lines)):
        if re.search('function',lines[i])!=None:
            lenOfFunction = braceMatch(lines[i:])
            for j in range(i,i+lenOfFunction):          #遍历contract中function每一行
                if(re.search(dangerous_call,lines[j]) != None):
                    yield j
    yield -1



def judge2_3(lines): #传入一个contract
    i = 0
    j = 0
    for i in range(0,len(lines)):
        if re.search('function',lines[i])!=None and re.search('private|internal',lines[i]) == None:
            lenOfFunction = braceMatch(lines[i:])
            for j in range(i,i+lenOfFunction):          #遍历contract中function每一行
                if re.search("selfdestruct *\(|suicide *\(",lines[j]):
                    yield j
    yield -1

def judge2_5(lines): #传入一个contract
    i = 0
    j = 0
    for i in range(0,len(lines)):
        if re.search("\+|-|\*|\/",lines[i])!= None and re.search("\+\+|--",lines[i])== None:
            yield i
def judge2_10(lines): #传入一个contract
    i = 0
    j = 0
    for i in range(0,len(lines)):   #遍历contract每一行
        if re.search('constructor',lines[i]) != None:
            if re.search('function',lines[i]):
                yield i
    yield -1

def judge2_10_1(lines,contractName): #传入一个contract,和contractName
    i = 0
    j = 0
    for i in range(1,len(lines)):   #遍历contract每一行
        if re.search("function *"+contractName,lines[i],re.IGNORECASE) != None:
            if re.search('function *'+contractName,lines[i]) == None:
                yield i
    yield -1

def judge2_11(lines): #传入一个contract
    i = 0
    j = 0
    for i in range(0,len(lines)):
        if re.search('function',lines[i])!=None and re.search("approve\(|transfer\(",lines[i]):
            error = True
            for j in range(i,len(lines)):
                if re.search('returns *\([\w0-9 ]*bool',lines[j]):
                    error = False
                if re.search('{',lines[j]):
                    break
            if error :
                yield  i
    yield -1



def judge2_12(lines,allevents): #传入一个contract
    i = 0
    j = 0
    events = []
    for i in range(0,len(lines)):                               #将event都放到一个列表中，为下一步检测emit检测做准备
        if re.search('event +([\w0-9]+)',lines[i]) != None:
            event = re.findall('event +([\w0-9]+)',lines[i])
            events = events + event
    events = allevents+events
    for i in range(0,len(lines)):
        if re.search('function',lines[i])!=None and re.search("approve|transfer|_approve|_transfer",lines[i]) !=None:
            lenOfFunction = braceMatch(lines[i:])
            safe = False
            s = i;
            while(s<len(lines)):
                if re.search('{',lines[s]):
                    break;
                s += 1
            for j in range(s,i+lenOfFunction):          #遍历contract中function每一行

                for event in events:
                    if re.search(event+"|emit",lines[j])!= None and re.search('function',lines[j])==None: #触发事件函数安全
                        safe = True
                        break;
                if safe:
                    break;
            if safe == False:
                yield i

def judge2_13(lines): #传入一个contract
    i = 0
    j = 0
    for i in range(0,len(lines)):

        if re.search('function',lines[i])!=None and re.search("_transfer|transfer",lines[i])!=None:
            lenOfFunction = braceMatch(lines[i:])
            tag1 = False
            tag2 = False
            for j in range(i,i+lenOfFunction):          #遍历contract中function每一行

                if re.search("require", lines[j]) != None:
                    tag1 = True
                if tag1 and re.search("!= *address *\( *0 *\) *\)", lines[j]) != None:
                    tag2 = True

            if tag1 and tag2:
                yield -1
            else:
                yield i

def judge2_14(lines): #传入一个contract
    i = 0
    j = 0
    for i in range(0,len(lines)):
        if re.search('function',lines[i])!=None:
            lenOfFunction = braceMatch(lines[i:])
            for j in range(i,i+lenOfFunction):          #遍历contract中function每一行
                if re.search("allowance *\[ *msg\.sender *\] *\[ *_spender *\] *= +|_allowed|allowed *\[ *msg\.sender *\] *\[ *_spender *\] *= +",lines[j])!=None:
                    error = True
                    for k in range(i,j):
                        if re.search("require *\(",lines[k]) !=None :
                            error = False
                            break
                    if error:
                        yield j
    yield -1

def judge2_21(lines): #传入一个contract
    res = []
    lenOfFunction = 0
    for i in range(0,len(lines)):
        if lenOfFunction>0:
            lenOfFunction -=1
            continue
        if re.search('{',lines[i])!=None and re.search('contract',lines[i])==None:
            lenOfFunction = braceMatch(lines[i:])
        if re.search("private|public|constant|internal|event|using",lines[i])== None and re.search(";",lines[i]) != None and re.search('function|event',lines[i]) == None and re.search("[\w0-9]+",lines[i]):
            res.append(i)
    return res


def judge2_22(lines): #传入一个contract
    res = []
    structs = []
    lenOfFunction = 0
    for i in range(0,len(lines)):
        if lenOfFunction>0:
            lenOfFunction -=1
            continue
        if re.search('{',lines[i])!=None and re.search('contract',lines[i])==None:
            lenOfFunction = braceMatch(lines[i:])
        if re.search('struct',lines[i])!=None:
            structs += re.findall("struct +([\w0-9]*) *",lines[i])

    for i in range(0,len(lines)):
        for struct in structs:
            if re.search(" "+struct,lines[i]) and re.search("struct",lines[i]) == None and re.search('memory|storage',lines[i]) == None:
                res.append(i)
    return res


scanSimple = {
            "name": "",
            "severity": "",  # waring or info
            "lines": "",  # 行数
            "scan_version": None,
            "updated": "",
            "sha256": "",
            "comment": "",
            "address": "",
            "code": "",
            "timestamp": "",
            "type": "",  # 写
            "cve": "",
            "description": "The compiler version must be determined version",  # 写
            "func": ""}
Data = {"compiler_version": "v0.4.8+commit.60cc1668",
        "token_transfers": "F",
        "contract_source_code": "",
        "transactions": 186497,
        "token_addr": "0x08d32b0da63e2C3bcF8019c9c5d849d7a9d791e6",
        "code": "",
        "scan": [],
        "holdings_count": 41,
        "updated": "2019-01-29 01:43:28",
        "contract_name": "DentacoinToken",
        "token_name": "Dentacoin",
        "token_rating": 167088,
        "standard": "ERC-20",
        "contract_addr": "0x08d32b0da63e2C3bcF8019c9c5d849d7a9d791e6",
        "dateVerified": None,
        "balance_eth": 1.375369847877531,
        "sha256": "31a56a0a53566b3dce303c4d8706d4a5b8fa703e1097385fb29d01c967bf00ab",
        "creator_address": "0xc99f67433019d1da18c311e767faa2b8ec250886",
        "is_top_token": True,
        "balance_usd": 142.89,
        "scan_information_count": 4,
        "scan_warning_count": 6
        }
Json = {"status_code": 10200, "msg": "sucess", "data": Data}

def addScan(type,security,description,lines,code):
    res = scanSimple.copy()
    res["type"] = type
    res["security"] = security
    res["description"] = description
    res["lines"] = lines
    res["code"] = code.strip()
    Json["data"]["scan"].append(res)

#判断两个字典是不是相同的，用于重复提示的去除
def sameDict(dict1,dict2):
    for k in dict1.keys():
        if(dict1[k]!=dict2[k]):
            return False
    return True




######################################################################################
#                                 以上写def的函数                                    #
######################################################################################


class Audition:
    def audit(self,lines):
        infos = []          #表示info信息的列表
        warnings = []       #表示warning信息的列表
                            #json 部分数据结构的定义
        Data["scan"].clear()
        #实现2.1的主函数
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_1(lines[i:i+lenOfContract]):
                        if n != -1:
                            infos.append("info: rule 2.01 Feature function is found.please confirm  feature function is not vulnerable. in "+ str(1+i+n)+" row.")
                            res = scanSimple.copy()
                            res["type"] = "Unauthorized assignment"
                            res["severity"] = "info"
                            res["description"] = " Contract owner or creater ,transferOwnership function possible found。Contract fields that can be modified by any user must be inspected。Please review this function is not vulnerable"
                            res["lines"] = str(1+i+n)
                            res["code"] = lines[i+n].strip()
                            Json["data"]["scan"].append(res)
                            warnings.append("warning: rule 2.01 Please confirm that the function that assigns the owner member is private or internal. in "+ str(1+i+n)+" row.")
                            res = scanSimple.copy()
                            res["type"] = "Unauthorized assignment"
                            res["severity"] = "warning"
                            res["description"] = "Please confirm that the function assigns the owner member is private or internal. Unrestricted writes indicate parts in the contract storage that are universally writable by all users. This can be extremely dangerous if the writes are to sensitive fields of the contract, such as owner."
                            res["lines"] = str(1 + i + n)
                            res["code"] = lines[i + n].strip()
                            Json["data"]["scan"].append(res)
        except BaseException:
            print("扫描2.1时出现异常")



        #完成需求2.2============================================================================以下


        #实现2.2的主函数
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_2(lines[i:i+lenOfContract]):
                         if n != -1:
                             res = scanSimple.copy()
                             res["type"] = "unsafe call or delegatecall"
                             res["severity"] = "warning"
                             res["description"] = "Unsafe using delegatecall or call potentially lead to inject data issue."
                             res["lines"] = str(1 + i + n)
                             res["code"] = lines[i + n].strip()
                             Json["data"]["scan"].append(res)
                             warnings.append("warning: rule 2.02 delegatecall or call potentially lead to inject data issue."+ " in "+ str(1+i+n)+" row.")
        except BaseException:
            print("扫描2.2时出现异常")

        #完成需求2.3========================================================================以下  The operation destruct contract unrestricted
        #寻找contract中的function中的selfdestruct语句，向上寻找判断语句
        #demo 具体实现根据下一种方法




        #实现2.3的主函数

        try:
            for i in range(0,len(lines)):
                if re.search("selfdestruct *\(|suicide *\(", lines[i]):
                    res = scanSimple.copy()
                    res["type"] = "selfdestruct or suicide function detected"
                    res["severity"] = "info"
                    res["description"] = "selfdestruct or suicide function is found.please confirm  feature function is not vulnerable."
                    res["lines"] = str(1 + i  )
                    res["code"] = lines[i].strip()
                    Json["data"]["scan"].append(res)
                    infos.append("info: rule 2.03 Feature function is found.please confirm  feature function is not vulnerable."+ " in "+str(i+1)+" row.")
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_3(lines[i:i+lenOfContract]):
                        if n != -1:
                            res = scanSimple.copy()
                            res["type"] = "unsafe selfdestruct or suicide function"
                            res["severity"] = "warning"
                            res["description"] = "The operation destruct contract unrestricted."
                            res["lines"] = str(1 + i + n)
                            res["code"] = lines[i + n].strip()
                            Json["data"]["scan"].append(res)
                            warnings.append("warning: rule 2.03 The operation destruct contract unrestricted. in "+ str(1+i+n)+" row.")

        except BaseException:
            print("扫描2.3时出现异常")

        #完成需求2.4========================================================================以下:Reentry issues
        key_word = '.call.value *\('   #key匹配规则 value错误名称 2.4

        try:
            for line in lines:
                    if(re.search(key_word,line)!=None):
                        res = Json.copy()
                        res["type"] = "reentry attack risks."
                        res["severity"] = "warning"
                        res["description"] = "Unsafe call.value calling potentially lead to re-entrancy vulnerability."
                        res["lines"] = str(1 + lines.index(line))
                        res["code"] = lines[lines.index(line)].strip()
                        Json["data"]["scan"].append(res)
                        warnings.append("warning: rule 2.04 call.value potentially lead to re-entrancy vulnerability."+" in "+ str(1+lines.index(line)) + " row.")
        except BaseException:
            print("扫描2.4时出现异常")

        #完成需求2.5========================================================================以下 :integer overflow



        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if re.match(' *contract +',line) and re.search('math',line,re.IGNORECASE) == None:
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_5(lines[i:i+lenOfContract]):
                        if n!=-1:
                            res = scanSimple.copy()
                            res["type"] = "integer overflow"
                            res["severity"] = "warning"
                            res["description"] = "The operation might cause integer overflow."
                            res["lines"] = str(1+i+n)
                            res["code"] = lines[i+n].strip()
                            Json["data"]["scan"].append(res)
                            warnings.append("warning: rule 2.05 The operation might cause integer overflow in "+str(1+i+n)+" row. Please use Safemath.")

        except:
            print("2.5在运行中出现异常")

        #完成需求2.6========================================================================以下 :Bad Randomness issuse

        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if re.search('block\.timestamp|blockhash\(|block\.difficulty|block\.number',line):
                    res = scanSimple.copy()
                    res["type"] = "bad random number"
                    res["severity"] = "info"
                    res["description"] = "Some block info or variable is found. please confirm PRNG(pseudo-random number generator) is safe."
                    res["lines"] = str(1 + i)
                    res["code"] = lines[i].strip()
                    Json["data"]["scan"].append(res)
                    infos.append("info: rule 2.06, Some block info variable is found.please confirm PRNG is safe. in "+ str(1+i)+" row.")

        except BaseException:
            print("扫描2.6时出现异常")
        #完成需求2.7========================================================================以下

        try:
            for line in lines:
                    if(re.search('tx.origin *== *[0-9w]+',line)!=None):
                        res = scanSimple.copy()
                        res["type"] = "misuse of tx.origin"
                        res["severity"] = "info"
                        res["description"] = "Authorization checks based on the tx.origin can result in dangerous callback attacks. Please review this function is not vulnerable."
                        res["lines"] = str(1+lines.index(line))
                        res["code"] = lines[lines.index(line)].strip()
                        Json["data"]["scan"].append(res)
                        infos.append("info: rule 2.07，Feature function is found.please confirm  feature function is not vulnerable."+" in "+ str(1+lines.index(line)) + "row.")
                        res = scanSimple.copy()
                        res["type"] = "authorization through tx.origin"
                        res["severity"] = "warning"
                        res["description"] = "Tx.origin should not be used for authorization."
                        res["lines"] = str(1+lines.index(line))
                        res["code"] = lines[lines.index(line)].strip()
                        Json["data"]["scan"].append(res)
                        warnings.append("warning: rule 2.07， Tx.origin should not be used for authorization. Use msg.sender instead."+" in "+ str(1+lines.index(line)) + "row.")
        except BaseException:
            print("扫描2.7时出现异常")

        #完成需求2.8========================================================================以下 :Incompatible ERC2.0 Standard

        #2.8
        try:
            alternativeDict = {"suicide":"selfdestruct(address)","block.blockhash":"blockhash(uint)","sha3":"keccak256()","callcode":"delegatecall()","throw":"revert()","msg.gas":"gasleft"}
            for i in range(0,len(lines)):
                line = lines[i]
                for key in alternativeDict.keys():
                    if(re.search(key,line)):
                        res = scanSimple.copy()
                        res["type"] = "use of deprecated solidity functions"
                        res["severity"] = "warning"
                        res["description"] = "use of deprecated solidity functions"
                        res["lines"] = str(i+1)
                        res["code"] = lines[i].strip()
                        Json["data"]["scan"].append(res)
                        warnings.append("warning: rule 2.08 Incompatible ERC2.0 Standard in "+str(1+i)+" row. "+key + " is deprecated, please use "+alternativeDict[key]+".")


            for i in range(0,len(lines)):
                if re.search('function',lines[i])!=None :
                    j = i
                    for j in range(i,len(lines)):
                        if re.search('constant',lines[j]):
                            res = scanSimple.copy()
                            res["type"] = "use of deprecated solidity functions"
                            res["severity"] = "warning"
                            res["description"] = "use of deprecated solidity functions"
                            res["lines"] = str(i+1)
                            res["code"] = lines[i].strip()
                            Json["data"]["scan"].append(res)
                            warnings.append("warning: rule 2.08 Incompatible ERC2.0 Standard in " + str(1 + i) + " row. " + "constant" + " is deprecated, please use " + "view" + ".")
                        if re.search('{',lines[j]):
                            break;
                    i = j+1

        except BaseException:
            print("扫描2.08时出现异常")




        #完成需求2.9========================================================================以下 :Please lock pragmas to specific compiler version
        #检查编译器版本，如果编译器版本合法记录编译器版本
        version = ""            #全局变量表示版本信息

        try:
            for line in lines:
                if line.isspace() == False:
                    if re.search("pragma +solidity",line) != None:
                        if re.match(" *pragma +solidity +0\.[0-5]\.[0-9]* *;",line) == None:
                            res = scanSimple.copy()
                            res["type"] = "unknown compiler version"
                            res["severity"] = "warning"
                            res["description"] = "Please using pragma lock solidity compiler to specific version."
                            res["lines"] = ""
                            res["code"] = ""
                            Json["data"]["scan"].append(res)
                            warnings.append("warning: rule 2.09 Please using pragma lock solidity compiler to specific version.")
                            break
                        else:
                            version = re.findall(" *pragma +solidity +(0\.[0-5]\.[0-9]*) *;", line)[0]
                            version = version.split('.')
                            version = list(map(int, version))
                    else:
                        addScan("unknown compiler version","warning","Please using pragma lock solidity compiler to specific version.","","")
                        warnings.append("warning: rule 2.09  Please using pragma lock solidity compiler to specific version.")
                    break
        except:
            print("扫描2.09时出现异常")


        #完成需求2.10========================================================================以下 :Constructor might be compiled to a normal function
        #这一条在文档中没有给出合适的提示信息：info或者warning
        #检查构造函数
        #检查版本是否是0.4.22以前


        try:
            passThis = False
            if len(version) == 0:
                passThis = True
                addScan("Uncertain compiler version","info"," Solidity compiler version is not found,can not confirm constructor function .","","")
                infos.append("info: rule 2.10 Solidity compiler version is not found,can not confirm constructor function .")
            if passThis == False:
                versionNew = False
                if version[1]>4:
                    versionNew = True
                elif version[1] == 4 and version[2]>=22:
                    versionNew = True

            if passThis == False:
                #如果是新版本（0.4.22及以后的版本）检查构造函数 检查：constructor如果加了function给出提示
                if versionNew:
                    for i in range(0, len(lines)):
                        line = lines[i]
                        if (re.match(' *contract +[\w0-9]', line)):
                            lenOfContract = braceMatch(lines[i:])
                            for n in judge2_10(lines[i:i + lenOfContract]):
                                if  n!= -1:
                                    addScan("Constructor detected","info","Constructor function is found. please confirm  constructor function is not vulnerable.",str(1+i+n),lines[i+n])
                                    infos.append('info: rule 2.10 Constructor function is found.please confirm  constructor function is not vulnerable. in ' + str(1+i+n) + " row.")
                #旧版本 检查构造函数：如果出现函数大小写与contractName相同，但是大小写不同，给出提示
                else:
                    for i in range(0, len(lines)):
                        line = lines[i]
                        if (re.match(' *contract +[\w0-9]*', line)):
                            contractName = re.findall(' *contract +([\w0-9]*)',line)[0]
                            lenOfContract = braceMatch(lines[i:])
                            for n in judge2_10_1(lines[i:i + lenOfContract],contractName):
                                if  n!= -1:
                                    addScan("Constructor detected", "info","Constructor function is found. please confirm  constructor function is not vulnerable.",str(1 + i + n), lines[i + n])
                                    infos.append('warning: rule 2.10 Constructor might be compiled to a normal function in ' + str(1+i + n) + " row.")
            if passThis == True:
                 for i in range(0, len(lines)):
                     line = lines[i]
                     if (re.match(' *contract +[\w0-9]*', line)):
                         contractName = re.findall(' *contract +([\w0-9]*)', line)[0]
                         lenOfContract = braceMatch(lines[i:])
                         for n in judge2_10_1(lines[i:i + lenOfContract], contractName):
                             if n != -1:
                                 addScan("Suspected constructor", "info"," Constructor might be compiled to a normal function.",str(1 + i + n), lines[i+n])
                                 infos.append('info: rule 2.10 Constructor might be compiled to a normal function in ' + str(1 + i + n) + " row.")
                 for i in range(0, len(lines)):
                     line = lines[i]
                     if (re.match(' *contract +[\w0-9]', line)):
                         lenOfContract = braceMatch(lines[i:])
                         for n in judge2_10(lines[i:i + lenOfContract]):
                             if n != -1:
                                 addScan("Suspected constructor", "info"," Constructor might be compiled to a normal function.",str(1 + i + n), lines[i+n])
                                 infos.append('info: rule 2.10 Constructor might be compiled to a normal function. in ' + str(1 + i + n) + " row.")
        except BaseException:
            print("扫描2.10时出现异常")

        #完成需求2.11========================================================================以下 :


        #实现2.11的主函数
        try:

            for i in range(0,len(lines)):
                line = lines[i]
                if re.search("function",line) != None and re.search("transfer|approve|transferFrom _transfer|_approve _transferFrom",line,re.IGNORECASE)!=None :
                    addScan("transfer or approve function detected","info","Transfer or approve function is found。please review this funtion is not vulnerable",str(i+1),lines[i])
                    infos.append("info: rule 2.11-2.14 Feature function is found.please confirm  feature function is not vulnerable. in "+str(i+1)+" row." )


            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_11(lines[i:i+lenOfContract]):
                        if n !=-1:
                            addScan("Incompatible ERC2.0 Standard","warning","The function contains transfer and approve should return bool.",str(i+n+1),lines[i+n])
                            warnings.append("warning: rule 2.11 The function contains transfer transferFrom  and approve should return bool. in " + str(1+i+n)+" row.")
        except BaseException:
            print("扫描2.11时出现异常")


        #完成需求2.12========================================================================以下 :The function contains transfer and approve emit event.

        allevents = []

        for i in range(0,len(lines)):
            line = lines[i]
            if re.search('event +([\w0-9]+)', line) != None:
                event = re.findall('event +([\w0-9]+)', line)
                allevents = allevents+event



        #实现2.12的主函数
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_12(lines[i:i+lenOfContract],allevents):
                        if n!=-1:
                            addScan("unsafe transfer funtion","info"," The function contains transfer and approve should emit event.",str(1+i+n),lines[i+n])
                            infos.append("info: rule 2.12 The function contains transfer and approve should emit event. in " + str(1+i+n)+" row.")


        except BaseException:
            print("扫描2.12时出现异常")


        #完成需求2.13========================================================================以下 :Transfer function should using require/assert/revert/throw keywords  throw a exception to make return value is zero.





        #实现2.13的主函数
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_13(lines[i:i+lenOfContract]):
                        if n!= -1:
                            addScan("unsafe transfer funtion","warning","Transfer function should use require keywords  throw a exception  making return value is zero and making sure to address is not zero.",str(1+i+n),lines[i+n])
                            warnings.append("warning: rule 2.13 Transfer function should using require keywords  throw a exception to make return value is zero and make sure to address is not 0. in "+ str(1+i+n)+" row.")
        except BaseException:
            print("扫描2.13时出现异常")
        #完成需求2.14========================================================================以下 : Transfer function should using require keywords set value and allowance[msg.sender][_spender] to zero.





        #实现2.14的主函数
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    for n in judge2_14(lines[i:i+lenOfContract]):
                        if n !=-1:
                            addScan("race condition issuse","warning","Approve have exist race condition. Maybe forget write require((_amount == 0)||(allowed[msg.sender][_spender] == 0).",str(1+i+n),lines[i+n])
                            warnings.append("warning: rule 2.14 approve function  should using require keywords set value and allowance[msg.sender][_spender] to zero. in "+ str(1+i+n)+" row.")
        except BaseException:
            print("扫描2.14时出现异常")

        #完成需求2.15========================================================================以下 : Please confirm the count of loop cannot be controled and be to too large.
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if re.search('do *{|while *\(|for *\(|new \+\[',line) !=None:
                    addScan("loop function detected.","info","Please review the count of loop cannot be controled and be to too large.",str(i+1),lines[i])
                    infos.append("info: rule 2.15 Please confirm the count of loop cannot be controled and be to too large in "+ str(1+i)+' row.')
        except BaseException:
            print("扫描2.15时出现异常")
        #完成需求2.16========================================================================以下 : Exclude the risk of replay attack.

        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if re.search('transferProxy *\(',line):
                    addScan("TransferProxy detected","info","TransferProxy function is found,please comfirm transferProxy nonce in transferProxy funtion  is safe.",str(i+1),lines[i])
                    infos.append("info: rule 2.16 TransferProxy function is found,please comfirm transferProxy nonce is ok. in "+ str(1+i)+' row.')
        except BaseException:
            print("扫描2.16时出现异常")
        #完成需求2.17========================================================================以下 : Replace assert of require.
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if re.search('assert *\(',line):
                    addScan("Incompatible ERC2.0 Standard","info","Please replace assert keyword by require keyword in judgment statement.",str(1+i),lines[i])
                    infos.append("info: rule 2.17 Please replace assert keyword by require keyword in judgment statement. in "+ str(1+i)+' row.')
        except BaseException:
            print("扫描2.17时出现异常")
        #完成需求2.18========================================================================以下 : Replace send of transfer.

        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if re.search('send *\(',line):
                    addScan("incompatible erc20 Standard","info","Please replace send function  by transfer function.",str(i+1),lines[i])
                    infos.append("info: rule 2.18  Please replace send function  by transfer function. in  "+ str(1+i)+' row.')

        except BaseException:
            print("扫描2.18时出现异常")

        #完成需求2.19========================================================================以下 : warning: check the privilige of function.
        #权限控制(owner 赋值一类)


        #完成需求2.20========================================================================以下 :

        try:
            for i in range(0,len(lines)):
                if re.search("refund|_refund",lines[i])!=None and re.search("function",lines[i])!=None:
                    addScan("refund funtion detected","info","Refund is found, Please confirm balances[msg.sender] is setted to 0.",str(i+1),lines[i])
                    infos.append("info: rule 2.20 function  refund is found, please confirm balances[msg.sender] setting to 0; in " +str(i+1)+" row.")

        except:
            print("扫描2.20时出现异常")
        #完成需求2.21========================================================================以下 : 检测成员变量是声明权限




        #实现2.21的主函数
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    res = judge2_21(lines[i:i+lenOfContract])
                    if(len(res)>0):
                        for r in res:
                            addScan("state variable default visibility","info","Variables can be specified as being public, internal or private. Explicitly define visibility for all state variables.",str(1+i+r),lines[i+r])
                            infos.append("info: rule 2.21 Variables can be specified as being public, internal or private. Explicitly define visibility for all state variables. in "+ str(1+i+r)+" row.")

        except BaseException:
            print("扫描2.21时出现异常")

        #完成需求2.22========================================================================以下 : 检测结构体声明是否使用storage或者memory





        #实现2.22的主函数
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if(re.match(' *contract +',line)):
                    lenOfContract = braceMatch(lines[i:])
                    res = judge2_22(lines[i:i+lenOfContract])
                    if(len(res)>0):
                        for r in res:
                            addScan("access of uninitialized pointer","info","It is recommended to explicitly specify the data location memory or storage when dealing with complex types to ensure they behave as expected.",str(1+i+r),lines[i+r])
                            infos.append("warning: rule 2.22 It is recommended to explicitly specify the data location memory or storage when dealing with complex types to ensure they behave as expected. in "+ str(1+i+r)+" row.")

        except BaseException:
            print("扫描2.22时出现异常")



        #完成需求2.23========================================================================以下 :

        try:
            for i in range(0 ,len(lines)):
                if re.search('assembly *\(',lines[i])!=None:
                    addScan("assembly keyword detected","info","Assembly keyword is found. The use of assembly should be minimal. A developer should not allow a user to assign arbitrary values to function type variables.",str(i+1),lines[i])
                    infos.append("info: rule 2.23, assembly is found. The use of assembly should be minimal. A developer should not allow a user to assign arbitrary values to function type variables. in "+str(i+1)+' row.')

        except BaseException:
            print("扫描2.23时出现异常")


        #完成需求2.24========================================================================以下 :
        #检测函数是否声明可见的权限
        try:
            for i in range(0,len(lines)):
                line = lines[i]
                if re.search('function',line) :
                    j = i
                    error = True
                    for j in range(i,len(lines)):
                        if re.search('private|public|internal|external|onlyOwner',lines[j]):
                            error = False
                        if re.search('{',lines[j]):
                            break
                    if error:
                        addScan("function default visibility ","info","Functions that do not have a function visibility type specified are public by default. This can lead to a vulnerability if a developer forgot to set the visibility and a malicious user is able to make unauthorized or unintended state changes.",str(i+1),lines[i])
                        infos.append("info: rule 2.24 Functions that do not have a function visibility type specified are public by default. This can lead to a vulnerability if a developer forgot to set the visibility and a malicious user is able to make unauthorized or unintended state changes. in "+ str(1+i) + " row.")
                    i = j+1





        except BaseException:
            print("扫描2.24时出现异常")

            #infos与warnings去重

        infos       = {}.fromkeys(infos).keys()
        warnings    = {}.fromkeys(warnings).keys()

        '''
        #输出info和warning信息
        res = ""
        res = '='*75+"infos"+'='*75
        res += '\n'
        for info in infos:
            res += info
            res += '\n'
        res+=('='*75+"warnings"+'='*75)
        res += '\n'
        for warning in warnings:
            res +=warning
            res += '\n'
        '''
        oldscans = Json["data"]["scan"]
        newscans = []
        for dict in oldscans:
            for d in newscans:
                if sameDict(dict,d):
                    break
            newscans.append(dict)


        Json["data"]["scan"] = newscans



        print(json.dumps(Json, sort_keys=False, indent=4, separators=(',', ':')))
        return Json
