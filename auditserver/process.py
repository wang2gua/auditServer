import re


#处理注释=========================================================================以下
#处理“//”
def findnotation(s):
    s = s[0]
    for i in range(0,len(s)):
        if s[i]=='/' and s[i+1] == '/':
            return i

#处理“/**/”
def findLeftAnnotation(s):
    if isinstance(s,list):
        s = s[0]
    for i in range(0,len(s)):
        if s[i] == '/' and s[i+1] == '*':
            return  i

def findRightAnnotation(s):
    if isinstance(s,list):
        s = s[0]
    for i in range(0,len(s)):
        if s[i] == '*' and s[i+1] == '/':
            return  i



class Process:
    def process_notation(self,lines):
        for i in range(0,len(lines)):
            if re.search('//',lines[i]):
                lines[i] = lines[i][:findnotation([lines[i]])]+" "



        for i in range(0,len(lines)):
            if re.search('/\*',lines[i]):
                j = i
                for j in range(i,len(lines)):
                    if re.search('\*/',lines[j]):
                        break
                if i == j:
                    lines[i] = lines[i] + ' '
                    lines[i] = lines[i][:findLeftAnnotation(lines[i])] +" "+ lines[i][findRightAnnotation(lines[i])+2:]
                else:
                    lines[i] = lines[i][:findLeftAnnotation(lines[i])]
                    lines[j] = lines[j]+" "
                    lines[j] = lines[j][findRightAnnotation(lines[j])+2:]
                    for k in range (i+1,j):
                        lines[k] = " "
                i = j+1
