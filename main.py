import sqlite3
import pandas as pd
import csv
import re
import subprocess, sys
import os
from packaging.version import Version, InvalidVersion
import fnmatch
import nmap
import time
from colorama import init
import math
from colorama import Fore, Back, Style
from art import tprint
import tabulate
from console_progressbar import ProgressBar
import datetime


# Сканированеи портов NMAPом
def Nmap_scan_ports(ip):
    #list_scan = {}
    #for ip in ip_list:
    nm = nmap.PortScanner()
    scan = nm.scan(ip[0], '22-443')
    sk = scan['scan']
        #list_scan.update(sk)
    return(sk)

#str(po_version[1]) закончить
#Get-ADComputer -Filter * -Properties ipv4Address,OperatingSystem
def Get_AD_Computers():
    result = subprocess.run(['powershell.exe', 'Get-ADComputer -Filter * -Properties ipv4Address,OperatingSystem > ip.csv'], capture_output=True, text=True)
    print (result.stdout)
    list_file = []
    with open('ip.txt', encoding='utf-16') as csvfile:
        count = -1
        list_pc = []
        for item in csvfile:
            if item != '\n':
                item_split = item.replace('\n',"").split(":")
                item_split[1] =  item_split[1][1:]
                while item_split[0][-1] == ' ':
                    item_split[0] = item_split[0][:-1]
                count += 1
                if count == 10:
                    count = -1
                    list_file.append(list_pc)
                    list_pc = []
                else:
                    list_pc.append(item_split)

                #list_file.append(item_split)

    conn_sqlite = sqlite3.connect('./DB.db')
    cursor_sqlite = conn_sqlite.cursor()    
    query = "DELETE FROM Users"
    cursor_sqlite.execute(query)
    conn_sqlite.commit()
    users = []
    for i in list_file:
        query = "INSERT INTO Users (dnsHostName, enabled, name, os, ip) VALUES ('" + i[1][1] + "', '" + i[2][1] + "', '" + i[4][1] + "', '" + i[7][1] +"', '" + i[3][1] + "')"
        cursor_sqlite.execute(query)
        conn_sqlite.commit()
        users.append([ i[1][1], i[2][1], i[4][1], i[7][1], i[3][1] ])
    conn_sqlite.close()
    return(users)

def Get_ip():
    conn_sqlite = sqlite3.connect('./DB.db')
    cursor_sqlite = conn_sqlite.cursor()    
    query = "SELECT ip FROM Users"
    cursor_sqlite.execute(query)
    ip = cursor_sqlite.fetchall()
    conn_sqlite.close()
    return ip

def Restyle_po_version(po_version):
    try:
        vers = Version(po_version)
        return(vers)

    except InvalidVersion:
        version = po_version.replace(' ', '.')
        v = re.sub('[^0-9.-]+', '', version)
        while '..' in v:
            v = v.replace('..', '.')

        if "-" in v:
            v = Version('1')
        if v != "":
            if v == ".":
                v = Version('0')
            elif v[0] == ".":
                v = v[1:]
        else:
            pass
        
        if v[-1] == '.':
            v = v[:-1]

        vers = Version(v)
        return(vers)

# Вывод списка версий
def Restyle_version(string_version):
    list_version = []
    version_bdu_do = Version('1')
    version_bdu_ot = Version('1')
    if "," in string_version:
        split_string_version = string_version.split(", ")
        for str_v in split_string_version:
            po = string_version[string_version.find('(') + 1:string_version.find(')')]
            string_version = string_version.lower()
            split_string = string_version.split(" ")
            if "от" in str_v and "до" in str_v and "включительно" in str_v:
                for i,v in zip(range(len(split_string)), split_string):
                    if v =="от":
                        version_bdu_ot = Version(split_string[i+1])
                    if v =="до":
                        version_bdu_do = Version(split_string[i+1])
        
                list_version.append([po, ">=", version_bdu_ot,"<=", version_bdu_do])

            elif "от" in str_v and "до" in str_v :
                for i,v in zip(range(len(split_string)), split_string):
                    if v =="от":
                        version_bdu_ot = Version(split_string[i+1])
                    elif v =="до":
                        version_bdu_do = Version(split_string[i+1])
        
                list_version.append([po, ">", version_bdu_ot,"<", version_bdu_do])
                
            elif "до" in str_v and "включительно" in str_v:
                for i,v in zip(range(len(split_string)), split_string):
                    if v =="до":
                        version_bdu_do = Version(split_string[i+1])
                list_version.append([po, "<=" , version_bdu_do])        

            elif "до" in str_v:
                for i,v in zip(range(len(split_string)), split_string):
                    if v =="до":
                        version_bdu_do = Version(split_string[i+1])
                list_version.append([po, "<" , version_bdu_do])

            else:
                try:
                    v = str_v[:str_v.find('(') - 1]
                    str = v.split(" ")
                    if len(str)>1:
                        str_vers = ".".join(str)
                    else:
                        str_vers = v
                    vers = Version(str_vers).base_version    
                    list_version.append([po, "=" , vers])

                except InvalidVersion:
                    v = str_v[:str_v.find('(') - 1]
                    version = v.replace(' ', '.')
                    v = re.sub('[^0-9.-]+', '', version)
                    
                    while '..' in v:
                        v = v.replace('..', '.')

                    if "-" in v:
                        v = v.replace('-', '.')

                    if v != "":
                        if v == ".":
                            v = '0'
                        elif v == "-":
                            v = '1'
                        elif v[0] == ".":
                            v = v[1:]
                    else:
                        break
                    
                    if v[-1] == '.':
                        v = v[:-1]

                    vers = Version(v)
                    list_version.append([po, "=" , vers])

    else:
        po = string_version[string_version.find('(') + 1:string_version.find(')')]
        string_version = string_version.lower()
        split_string = string_version.split(" ")
        if "от" in string_version and "до" in string_version and "включительно" in string_version:
            for i,v in zip(range(len(split_string)), split_string):
                if v =="от":
                    version_bdu_ot = Version(split_string[i+1])
                if v =="до":
                    version_bdu_do = Version(split_string[i+1])
    
            list_version.append([po, ">=", version_bdu_ot,"<=", version_bdu_do])

        elif "от" in string_version and "до" in string_version :
            for i,v in zip(range(len(split_string)), split_string):
                if v =="от":
                    version_bdu_ot = Version(split_string[i+1])
                if v =="до":
                    version_bdu_do = Version(split_string[i+1])
    
            list_version.append([po, ">", version_bdu_ot,"<", version_bdu_do])
            
        elif "до" in string_version and "включительно" in string_version:
            for i,v in zip(range(len(split_string)), split_string):
                if v =="до":
                    version_bdu_do = Version(split_string[i+1])
            list_version.append([po, "<=" , version_bdu_do])        

        elif "до" in string_version:
            for i,v in zip(range(len(split_string)), split_string):
                if v =="до":
                    version_bdu_do = Version(split_string[i+1])
            list_version.append([po, "<" , version_bdu_do])

        else:
            try: 
                v =string_version[:string_version.find('(')-1]
                split_vers = v.split(" ")
                if len(split_vers)>1:
                    str_vers = ".".join(split_vers)
                else:
                    str_vers = v
                vers = Version(str_vers)    
                list_version.append([po, "=" , vers])

            except InvalidVersion:
                    v = string_version[:string_version.find('(') - 1]
                    version = v.replace(' ', '.')
                    v = re.sub('[^0-9.-]+', '', version)
                    if v == ".":
                        v = "0"
                    elif v[0] == ".":
                        v = v[1:]
                    elif v == "-":
                        v = "1"
                    vers = Version(v)
                    list_version.append([po, "=" , vers])
    
    return(list_version)

# Вычисление версии
def Math_Version(po_version, list_version):
    result = []
    for elem_list_version in list_version:
        if  elem_list_version[0] in po_version[0]:
            if len(elem_list_version)==5:
                if elem_list_version[1] == ">=" and elem_list_version[3] == "<=":
                    if elem_list_version[2] <= po_version[1] and po_version[1] <= elem_list_version[4]:
                        result.append(True)
                    else: result.append(False)
                if elem_list_version[1] == ">" and elem_list_version[3] == "<":
                    if elem_list_version[4] < po_version[1] and po_version[1] < elem_list_version[4]:
                        result.append(True)
                    else: result.append(False)        

            elif len(elem_list_version) == 3:
                if elem_list_version[1] == "<=":
                    if po_version[1] <= elem_list_version[2]:
                        result.append(True)
                    else: result.append(False)
                elif elem_list_version[1] == "<":
                    if po_version[1] < elem_list_version[2]:
                        result.append(True)
                    else: result.append(False)
                elif elem_list_version[1] == "=":
                    if po_version[1] == elem_list_version[2]:
                        result.append(True)
                    else: result.append(False)

            elif len(elem_list_version) == 0:
                result.append(False)
        else:
            result.append(False)
    
    if True in result:
        return True
    else: return False

# Выбор правильной версии
def Get_right_version(progs):
    list_version = []
    new_bdu = []
    for programs in progs:
        for bdu in progs[programs]:
            vers_program = [programs[2],Restyle_po_version(programs[3])]
            versions = Restyle_version(bdu[3])
            if versions != []:
                if Math_Version(vers_program,versions):
                    bdu = bdu + (programs[1],)
                    new_bdu.append(bdu)


            list_version.append(versions)
    
    print('\n' + str(len(new_bdu)) + " уязвимостей найдено\n")      
    return(new_bdu)

# Вывод программ в CSV
def Get_programs_in_PC():
    subprocess.Popen(["powershell","C:/Users/Администратор/Desktop/ADScanner/Invetn.ps1"], stdout=subprocess.PIPE)   

# Вывод списка программ из CSV в DB
def Get_program_in_CSV_to_DB():
    
    conn_sqlite = sqlite3.connect('./DB.db')
    cursor_sqlite = conn_sqlite.cursor()    
    query = "DELETE FROM Prodrams"
    cursor_sqlite.execute(query)
    conn_sqlite.commit()

    for file in os.listdir('.'):
        if fnmatch.fnmatch(file, 'InstalledPrograms-*.csv'):
            with open(file, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    rows = str(row)
                    rows_split = rows.split(':')
                    rows = rows_split[1].split(';')
                    if rows[0] == " 'VMware Tools":
                        continue
                    r = rows[0].replace("'", '')
                    while r[0] ==" ":
                        r = r[1:]
                    rows[0] = r
                    a = rows[1].replace('"', '')
                    b = rows[0].replace('"', '')
                    c = rows[4].replace('"', '')
                    program = [a, b, c]
                    
                    query = "INSERT INTO Prodrams (namePC, displayName, displayVersion) VALUES ('" + program[0] + "', '" + program[1] + "', '" + program[2] + "')"
                    cursor_sqlite.execute(query)
    conn_sqlite.commit()
    conn_sqlite.close()    


# Вывод списка программ из БД
def Get_programs_in_DB():
    conn_sqlite = sqlite3.connect('DB.db')
    cursor_sqlite = conn_sqlite.cursor()
    query = "SELECT * FROM Prodrams"
    cursor_sqlite.execute(query)
    programs = cursor_sqlite.fetchall()
    conn_sqlite.close()
    return(programs)

# Выбор названия программы
def Restyling_title(program):
    title = program.split(' ')
    check = title[1:2]
    title = title[:1]
    for t in check:
        if any(map(str.isdigit, t)) != True:
            title.append(t)
    title = " ".join(title)  
    return(title)
     
# Поиск уязвимостей в CSV
def Get_BDU_in_CSV(programs):
    language = ['Python', 'C++','C#', 'ODBC']
    count_vul = 0
    dict_vul = {}
    for program in programs:    
        list_language = [lang for lang in language if(lang in program[2])]
        if list_language == []:
            title = Restyling_title(program[2])
            list_vul_csv = Check_Version(title, program[3])
            dict_vul.setdefault(program, [])
            dict_vul[program].append(list_vul_csv)
            count_vul += 1
        else:
            lang = list_language[0]
            list_vul_csv = Check_Version(lang, program[3])
            dict_vul.setdefault(program, [])
            if list_vul_csv != []:
                for l in list_vul_csv:
                    dict_vul[program].append(l)
                    count_vul += 1  
    return([count_vul, dict_vul])
 
# Поиск уязвимостей в БД BDU
def Get_BDU_in_DB(programs):
    conn_sqlite = sqlite3.connect('DB.db')
    cursor_sqlite = conn_sqlite.cursor()
    language = ['Python', 'C++','C#', 'ODBC']
    count_vul = 0
    dict_vul = {}
    for program in programs:    
        list_language = [lang for lang in language if(lang in program[2])]
        if list_language == []:
            title = Restyling_title(program[2])
            cursor_sqlite.execute("SELECT * FROM BDU WHERE name GLOB '*"+ title +"*';")
            list = cursor_sqlite.fetchall()

            dict_vul.setdefault(program, [])
            if list != []:
                for l in list:
                    dict_vul[program].append(l)
                    count_vul += 1
        else:
            lang = list_language[0]
            cursor_sqlite.execute("SELECT * FROM BDU WHERE name GLOB '"+ lang +"';")
            list = cursor_sqlite.fetchall()

            dict_vul.setdefault(program, [])
            if list != []:
                for l in list:
                    dict_vul[program].append(l)
                    count_vul += 1
    conn_sqlite.close()
    return([count_vul, dict_vul])

def Get_ports_Nmap(list_ip):
    for ip in list_ip:
        subprocess.run(["powershell", './Nmap-Scan', ip[0]], timeout = 30, stdout=subprocess.PIPE)

def Get_ports_xml(ip_list):
    list = []
    for ip in ip_list:
        ip_file = ip + '.xml'
        for file in os.listdir('.'):
            if fnmatch.fnmatch(file, ip_file):
                with open(file, newline='') as xmlfile:
                    reader = csv.DictReader(xmlfile)
                    for row in reader:
                        list.append(row)
    print()

# Загрузка данных из xlsx в BDU
def Load_BDU():
    # Load the xlsx file
    excel_data = pd.read_excel('./vullist.xlsx')
    # Read the values of the file in the dataframe
    data = pd.DataFrame(excel_data, columns=['Идентификатор', 'Наименование уязвимости', 'Название ПО', 'Версия ПО', 'Тип ПО', 'Уровень опасности уязвимости', 'Возможные меры по устранению', 'Информация об устранении'])

    # подключение к базе данных SQLite
    conn_sqlite = sqlite3.connect('./DB.db')
    cursor_sqlite = conn_sqlite.cursor()    
    query = "DELETE FROM BDU"
    cursor_sqlite.execute(query)

    # добавление данных в таблицу SQLite
    for row in data.values:
        for index ,i in enumerate(row):
            if i != i:
                row[index] = 'Нет информации'
        for index ,i in enumerate(row):
            row[index] = re.sub(r"[*\']", '', row[index])
            row[index] = re.sub(r'"', '', row[index])
        query = "INSERT INTO BDU (id, nameBDU, name, version, type, level, measures, elimination) VALUES ('" + row[0] + "', '" + row[1] + "', '" + row[2] + "', '" + row[3] + "', '" + row[4] + "', '" + row[5] + "', '" + row[6] + "', '" + row[7] + "')"

        cursor_sqlite.execute(query)
    print('end')
    # сохранение изменений в базе данных SQLite
    conn_sqlite.commit()

    # закрытие соединений
    conn_sqlite.close()
    print("end")

def Get_ipComputer():
    script = open("Get-IP.ps1").read()

    startInfo = {
        "FileName": "powershell.exe",
        "Arguments": "-Command \"" + script + "\"",
        "UseShellExecute": False,
        "RedirectStandardOutput": True,
        "RedirectStandardError": True
    }
    process = { "StartInfo": startInfo }
    process.start()
    output = process.StandardOutput.readToEnd()
    error = process.StandardError.readToEnd()
    process.waitForExit()

def menu(list_option):
    menu = ''
    for option in list_option:
        menu += '\n' + str(list_option.index(option) + 1) + ' ' + str(option)
    print(menu)
    input_option = input('>> ')
    return(input_option)
    
def test():
    pb = ProgressBar(total=100,prefix='Here', suffix='Now', decimals=3, length=50, fill='X', zfill='-')
    pb.print_progress_bar()

    init()
    tprint("AD Scaner")

    data = [
        ['id', 'name', 'number']    
    ]
    data.append([Fore.GREEN + 'green text', Style.BRIGHT + 'bright',Style.BRIGHT + 'bright' + Style.RESET_ALL])
    results = tabulate.tabulate(data)
    print(results)
    print(Fore.GREEN + 'green text')
    print(Style.BRIGHT + 'bright' + Style.RESET_ALL)
    print('default')


    Get_AD_Computers()
    ip = Get_ip()
    ip.append(('192.168.246.128',))
    ports = {}
    for i in ip:
        port = Nmap_scan_ports(i)
        ports.update(port)
    Get_programs_in_PC()
    Get_program_in_CSV_to_DB()
    programs = Get_programs_in_DB()
    bdu_progs = Get_BDU_in_DB(programs)
    bdu_right = Get_right_version(bdu_progs[1])
    print()

def main():
    save_data = {}
    start_time = time.time()

    #Сканирование компьютеров сети
    print('\nСканирование компьютеров сети...')
    users = Get_AD_Computers()
    data = [ ['dnsHostName', 'enabled', 'name', 'os', 'ip']]
    for u in users:
        data.append(u)
    results = tabulate.tabulate(data)
    print(results)
    save_data.update({'Компьютеры сети': data})

    #Сканирование портов
    save_d  = {}
    ip = Get_ip()
    ip.append(('192.168.246.128',))
    ip.append(('192.168.224.128',))
    print('\nСканирование портов...')
    for i in ip:
        ports = Nmap_scan_ports(i)
        if ports != {}:
            if 'tcp' in ports[i[0]]:
                data = [['№', 'name', 'product']]
                for p, o in ports[i[0]]['tcp'].items():
                    d = [str(p),  o['name'], o['product']]
                    data.append(d)
                results = tabulate.tabulate(data)
                save_d.update({str(i[0]): data})
                print('\nОткрытые порты ' + str(i[0]))
                print(results)
                print()
            else: 
                text = 'Хост ' + str(i[0]) + ' не доступен'
                save_d.update({str(i[0]):'Хост недоступен'})
                print(text)
        else: 
            text = 'Хост ' + str(i[0]) + ' не доступен'
            save_d.update({str(i[0]):'Хост недоступен'})
            print(text)
    save_data.update({'Порты': save_d})

    Get_programs_in_PC()
    Get_program_in_CSV_to_DB()
    programs = Get_programs_in_DB()
    print('Программы компьютеров AD\n')
    data = [['Computer', 'PO', 'Version']]
    for p in programs:
        d = [p[1],  p[2], p[3]]
        data.append(d)
    results = tabulate.tabulate(data)
    save_data.update({'Программы': data})
    print(results)

    bdu_progs = Get_BDU_in_DB(programs)
    bdu_right = Get_right_version(bdu_progs[1])
    save_data.update({'БДУ': bdu_right})
    data = [ ['Хост', '№', 'Уровень опасности']]
    r = 0
    y = 0
    g = 0
    for b in bdu_right:
        check = b[5].split(' ')[0]
        if check == 'Высокий' or check == 'Критический':
            d = [b[8], Fore.RED + b[0],  b[5] + Style.RESET_ALL]
            r += 1
        elif check == 'Средний':
            d = [b[8], Fore.YELLOW + b[0], b[5] + Style.RESET_ALL]
            y += 1
        elif check == 'Низкий':
            d = [b[8], Fore.GREEN + b[0], b[5] + Style.RESET_ALL]
            g += 1
        else:
            d = [b[8], b[0] + Style.RESET_ALL, b[5]]
        data.append(d)
    results = tabulate.tabulate(data)
    print(results)
    print(f'Всего {r} опасных, {y} средних и {g} низких уязвимостей')
    print()
            
    end_time = time.time()
    print(str(math.ceil(end_time - start_time)) + ' сек работала программа')
    return(save_data)

def save_file(data):
    identy = str(datetime.date.today())
    path = './ScanAD(' + str(identy) +').xlsx'
    'Компьютеры сети '
    'Порты'
    'Программы'
    'БДУ'
    dnsHostName = []
    enabled = []
    name = []
    os = []
    ip = []
    for i in data['Компьютеры сети']:
        if i[0] == 'dnsHostName':
            data['Компьютеры сети'].pop(0)
        dnsHostName.append(i[0])
        enabled.append(i[1])
        name.append(i[2])
        os.append(i[3])
        ip.append(i[4])
    df1 = pd.DataFrame({
        'dnsHostName': dnsHostName, 
        'enabled': enabled, 
        'name': name, 
        'os': os, 
        'ip': ip
    })
    
    
    num = []
    name = []
    product = []
    vne_dostupa = []
    hosts = []
    P = data['Порты']
    for i,v in P.items():
        
        if v == 'Хост недоступен': 
            vne_dostupa.append(i)
        else:
            for f in v:
                if i in hosts:
                    hosts.append('')
                else:
                    hosts.append(i)
                num.append(f[0])
                name.append(f[1])
                product.append(f[2])
    df2 = pd.DataFrame({
        'host': hosts,
        '№': num, 
        'name': name, 
        'product': product
    })

    df3 = pd.DataFrame({
        'Хост': vne_dostupa, 
    })
    
    computer = []
    po = []
    version = []
    for v in data['Программы']:
        if v[0] in computer:
            computer.append('')
        else:
            computer.append(v[0])
        po.append(v[1])
        version.append(v[2])
    df4 = pd.DataFrame({
        'Computer': computer,
        'PO': po, 
        'Version': version
    })

    num = []
    nameBDU = []
    name = []
    version = []
    type = []
    level = []
    measures = []
    elimination = []
    pc = []
    for v in data['БДУ']:
        if v[8] in pc:
            pc.append('')
        else:
            pc.append(v[8])
        num.append(v[0])
        nameBDU.append(v[1])
        name.append(v[2])
        version.append(v[3])
        type.append(v[4])
        level.append(v[5])
        measures.append(v[6])
        elimination.append(v[7])
    df5 = pd.DataFrame({
        'Хост': pc,
        '№': num,
        'Название уязвимости': nameBDU, 
        'Название ПО': name,
        'Версия ПО': version,
        'Тип ПО': type, 
        'Уровень опасности': level,
        'Меры по устранению': measures,
        'Информация об устранении': elimination
    })

    with pd.ExcelWriter(path) as writer:
   
        df1.to_excel(writer, sheet_name="Компьютеры сети", index=False)
        df2.to_excel(writer, sheet_name="Порты", index=False)
        df3.to_excel(writer, sheet_name="Недоступные хосты", index=False)
        df4.to_excel(writer, sheet_name="Программы", index=False)
        df5.to_excel(writer, sheet_name="Уязвимости", index=False)

    print('Данные сканирования сохранены' + path)



if __name__ == '__main__':
    
    init()
    tprint("AD Scaner")
    print('Начать сканирование?')
    option = menu(['Да', 'Нет'])
    while str(option) == '1':
        save_data = main()
        print('Сохранить результаты?\n')
        option_save = menu(['Да', 'Нет'])
        if option_save == '1':
            save_file(save_data)
        print('Повторить сканирование?\n')
        option = menu(['Да', 'Нет (Выход)'])
