# -*- coding: utf-8 -*-

from itertools import product
from future.utils import viewitems

COMMANDS = {
    '9420': '',
    '9429': '',
    '9425': '',
    '9426': '',
    '94a7': '',
    '942a': '',
    '94ab': '',
    '942c': '',
    '94ae': '',
    '942f': '',
    '9779': '<$>{break}<$>',
    '9775': '<$>{break}<$>',
    '9776': '<$>{break}<$>',
    '9770': '<$>{break}<$>',
    '9773': '<$>{break}<$>',
    '10c8': '<$>{break}<$>',
    '10c2': '<$>{break}<$>',
    '166e': '<$>{break}<$>{italic}<$>',
    '166d': '<$>{break}<$>',
    '166b': '<$>{break}<$>',
    '10c4': '<$>{break}<$>',
    '9473': '<$>{break}<$>',
    '977f': '<$>{break}<$>',
    '977a': '<$>{break}<$>',
    '1668': '<$>{break}<$>',
    '1667': '<$>{break}<$>',
    '1664': '<$>{break}<$>',
    '1661': '<$>{break}<$>',
    '10ce': '<$>{break}<$>{italic}<$>',
    '94c8': '<$>{break}<$>',
    '94c7': '<$>{break}<$>',
    '94c4': '<$>{break}<$>',
    '94c2': '<$>{break}<$>',
    '94c1': '<$>{break}<$>',
    '915e': '<$>{break}<$>',
    '915d': '<$>{break}<$>',
    '915b': '<$>{break}<$>',
    '925d': '<$>{break}<$>',
    '925e': '<$>{break}<$>',
    '925b': '<$>{break}<$>',
    '97e6': '<$>{break}<$>',
    '97e5': '<$>{break}<$>',
    '97e3': '<$>{break}<$>',
    '97e0': '<$>{break}<$>',
    '97e9': '<$>{break}<$>',
    '9154': '<$>{break}<$>',
    '9157': '<$>{break}<$>',
    '9151': '<$>{break}<$>',
    '9258': '<$>{break}<$>',
    '9152': '<$>{break}<$>',
    '9257': '<$>{break}<$>',
    '9254': '<$>{break}<$>',
    '9252': '<$>{break}<$>',
    '9158': '<$>{break}<$>',
    '9251': '<$>{break}<$>',
    '94cd': '<$>{break}<$>',
    '94ce': '<$>{break}<$>{italic}<$>',
    '94cb': '<$>{break}<$>',
    '97ef': '<$>{break}<$>{italic}<$>',
    '1373': '<$>{break}<$>',
    '97ec': '<$>{break}<$>',
    '97ea': '<$>{break}<$>',
    '15c7': '<$>{break}<$>',
    '974f': '<$>{break}<$>{italic}<$>',
    '10c1': '<$>{break}<$>',
    '974a': '<$>{break}<$>',
    '974c': '<$>{break}<$>',
    '10c7': '<$>{break}<$>',
    '976d': '<$>{break}<$>',
    '15d6': '<$>{break}<$>',
    '15d5': '<$>{break}<$>',
    '15d3': '<$>{break}<$>',
    '15d0': '<$>{break}<$>',
    '15d9': '<$>{break}<$>',
    '9745': '<$>{break}<$>',
    '9746': '<$>{break}<$>',
    '9740': '<$>{break}<$>',
    '9743': '<$>{break}<$>',
    '9749': '<$>{break}<$>',
    '15df': '<$>{break}<$>',
    '15dc': '<$>{break}<$>',
    '15da': '<$>{break}<$>',
    '15f8': '<$>{break}<$>',
    '94fe': '<$>{break}<$>',
    '94fd': '<$>{break}<$>',
    '94fc': '<$>{break}<$>',
    '94fb': '<$>{break}<$>',
    '944f': '<$>{break}<$>{italic}<$>',
    '944c': '<$>{break}<$>',
    '944a': '<$>{break}<$>',
    '92fc': '<$>{break}<$>',
    '1051': '<$>{break}<$>',
    '1052': '<$>{break}<$>',
    '1054': '<$>{break}<$>',
    '92fe': '<$>{break}<$>',
    '92fd': '<$>{break}<$>',
    '1058': '<$>{break}<$>',
    '157a': '<$>{break}<$>',
    '157f': '<$>{break}<$>',
    '9279': '<$>{break}<$>',
    '94f4': '<$>{break}<$>',
    '94f7': '<$>{break}<$>',
    '94f1': '<$>{break}<$>',
    '9449': '<$>{break}<$>',
    '92fb': '<$>{break}<$>',
    '9446': '<$>{break}<$>',
    '9445': '<$>{break}<$>',
    '9443': '<$>{break}<$>',
    '94f8': '<$>{break}<$>',
    '9440': '<$>{break}<$>',
    '1057': '<$>{break}<$>',
    '9245': '<$>{break}<$>',
    '92f2': '<$>{break}<$>',
    '1579': '<$>{break}<$>',
    '92f7': '<$>{break}<$>',
    '105e': '<$>{break}<$>',
    '92f4': '<$>{break}<$>',
    '1573': '<$>{break}<$>',
    '1570': '<$>{break}<$>',
    '1576': '<$>{break}<$>',
    '1575': '<$>{break}<$>',
    '16c1': '<$>{break}<$>',
    '16c2': '<$>{break}<$>',
    '9168': '<$>{break}<$>',
    '16c7': '<$>{break}<$>',
    '9164': '<$>{break}<$>',
    '9167': '<$>{break}<$>',
    '9161': '<$>{break}<$>',
    '9162': '<$>{break}<$>',
    '947f': '<$>{break}<$>',
    '91c2': '<$>{break}<$>',
    '91c1': '<$>{break}<$>',
    '91c7': '<$>{break}<$>',
    '91c4': '<$>{break}<$>',
    '13e3': '<$>{break}<$>',
    '91c8': '<$>{break}<$>',
    '91d0': '<$>{break}<$>',
    '13e5': '<$>{break}<$>',
    '13c8': '<$>{break}<$>',
    '16cb': '<$>{break}<$>',
    '16cd': '<$>{break}<$>',
    '16ce': '<$>{break}<$>{italic}<$>',
    '916d': '<$>{break}<$>',
    '916e': '<$>{break}<$>{italic}<$>',
    '916b': '<$>{break}<$>',
    '91d5': '<$>{break}<$>',
    '137a': '<$>{break}<$>',
    '91cb': '<$>{break}<$>',
    '91ce': '<$>{break}<$>{italic}<$>',
    '91cd': '<$>{break}<$>',
    '13ec': '<$>{break}<$>',
    '13c1': '<$>{break}<$>',
    '13ea': '<$>{break}<$>',
    '13ef': '<$>{break}<$>{italic}<$>',
    '94f2': '<$>{break}<$>',
    '97fb': '<$>{break}<$>',
    '97fc': '<$>{break}<$>',
    '1658': '<$>{break}<$>',
    '97fd': '<$>{break}<$>',
    '97fe': '<$>{break}<$>',
    '1652': '<$>{break}<$>',
    '1651': '<$>{break}<$>',
    '1657': '<$>{break}<$>',
    '1654': '<$>{break}<$>',
    '10cb': '<$>{break}<$>',
    '97f2': '<$>{break}<$>',
    '97f1': '<$>{break}<$>',
    '97f7': '<$>{break}<$>',
    '97f4': '<$>{break}<$>',
    '165b': '<$>{break}<$>',
    '97f8': '<$>{break}<$>',
    '165d': '<$>{break}<$>',
    '165e': '<$>{break}<$>',
    '15cd': '<$>{break}<$>',
    '10cd': '<$>{break}<$>',
    '9767': '<$>{break}<$>',
    '9249': '<$>{break}<$>',
    '1349': '<$>{break}<$>',
    '91d9': '<$>{break}<$>',
    '1340': '<$>{break}<$>',
    '91d3': '<$>{break}<$>',
    '9243': '<$>{break}<$>',
    '1343': '<$>{break}<$>',
    '91d6': '<$>{break}<$>',
    '1345': '<$>{break}<$>',
    '1346': '<$>{break}<$>',
    '9246': '<$>{break}<$>',
    '94e9': '<$>{break}<$>',
    '94e5': '<$>{break}<$>',
    '94e6': '<$>{break}<$>',
    '94e0': '<$>{break}<$>',
    '94e3': '<$>{break}<$>',
    '15ea': '<$>{break}<$>',
    '15ec': '<$>{break}<$>',
    '15ef': '<$>{break}<$>{italic}<$>',
    '16fe': '<$>{break}<$>',
    '16fd': '<$>{break}<$>',
    '16fc': '<$>{break}<$>',
    '16fb': '<$>{break}<$>',
    '1367': '<$>{break}<$>',
    '94ef': '<$>{break}<$>{italic}<$>',
    '94ea': '<$>{break}<$>',
    '94ec': '<$>{break}<$>',
    '924a': '<$>{break}<$>',
    '91dc': '<$>{break}<$>',
    '924c': '<$>{break}<$>',
    '91da': '<$>{break}<$>',
    '91df': '<$>{break}<$>',
    '134f': '<$>{break}<$>{italic}<$>',
    '924f': '<$>{break}<$>{italic}<$>',
    '16f8': '<$>{break}<$>',
    '16f7': '<$>{break}<$>',
    '16f4': '<$>{break}<$>',
    '16f2': '<$>{break}<$>',
    '16f1': '<$>{break}<$>',
    '15e0': '<$>{break}<$>',
    '15e3': '<$>{break}<$>',
    '15e5': '<$>{break}<$>',
    '15e6': '<$>{break}<$>',
    '15e9': '<$>{break}<$>',
    '9757': '<$>{break}<$>',
    '9754': '<$>{break}<$>',
    '9752': '<$>{break}<$>',
    '9751': '<$>{break}<$>',
    '9758': '<$>{break}<$>',
    '92f1': '<$>{break}<$>',
    '104c': '<$>{break}<$>',
    '104a': '<$>{break}<$>',
    '104f': '<$>{break}<$>{italic}<$>',
    '105d': '<$>{break}<$>',
    '92f8': '<$>{break}<$>',
    '975e': '<$>{break}<$>',
    '975d': '<$>{break}<$>',
    '975b': '<$>{break}<$>',
    '1043': '<$>{break}<$>',
    '1040': '<$>{break}<$>',
    '1046': '<$>{break}<$>',
    '1045': '<$>{break}<$>',
    '1049': '<$>{break}<$>',
    '9479': '<$>{break}<$>',
    '917f': '<$>{break}<$>',
    '9470': '<$>{break}<$>',
    '9476': '<$>{break}<$>',
    '917a': '<$>{break}<$>',
    '9475': '<$>{break}<$>',
    '927a': '<$>{break}<$>',
    '927f': '<$>{break}<$>',
    '134a': '<$>{break}<$>',
    '15fb': '<$>{break}<$>',
    '15fc': '<$>{break}<$>',
    '15fd': '<$>{break}<$>',
    '15fe': '<$>{break}<$>',
    '1546': '<$>{break}<$>',
    '1545': '<$>{break}<$>',
    '1543': '<$>{break}<$>',
    '1540': '<$>{break}<$>',
    '1549': '<$>{break}<$>',
    '13fd': '<$>{break}<$>',
    '13fe': '<$>{break}<$>',
    '13fb': '<$>{break}<$>',
    '13fc': '<$>{break}<$>',
    '92e9': '<$>{break}<$>',
    '92e6': '<$>{break}<$>',
    '9458': '<$>{break}<$>',
    '92e5': '<$>{break}<$>',
    '92e3': '<$>{break}<$>',
    '92e0': '<$>{break}<$>',
    '9270': '<$>{break}<$>',
    '9273': '<$>{break}<$>',
    '9275': '<$>{break}<$>',
    '9276': '<$>{break}<$>',
    '15f1': '<$>{break}<$>',
    '15f2': '<$>{break}<$>',
    '15f4': '<$>{break}<$>',
    '15f7': '<$>{break}<$>',
    '9179': '<$>{break}<$>',
    '9176': '<$>{break}<$>',
    '9175': '<$>{break}<$>',
    '947a': '<$>{break}<$>',
    '9173': '<$>{break}<$>',
    '9170': '<$>{break}<$>',
    '13f7': '<$>{break}<$>',
    '13f4': '<$>{break}<$>',
    '13f2': '<$>{break}<$>',
    '13f1': '<$>{break}<$>',
    '92ef': '<$>{break}<$>{italic}<$>',
    '92ec': '<$>{break}<$>',
    '13f8': '<$>{break}<$>',
    '92ea': '<$>{break}<$>',
    '154f': '<$>{break}<$>{italic}<$>',
    '154c': '<$>{break}<$>',
    '154a': '<$>{break}<$>',
    '16c4': '<$>{break}<$>',
    '16c8': '<$>{break}<$>',
    '97c8': '<$>{break}<$>',
    '164f': '<$>{break}<$>{italic}<$>',
    '164a': '<$>{break}<$>',
    '164c': '<$>{break}<$>',
    '1645': '<$>{break}<$>',
    '1646': '<$>{break}<$>',
    '1640': '<$>{break}<$>',
    '1643': '<$>{break}<$>',
    '1649': '<$>{break}<$>',
    '94df': '<$>{break}<$>',
    '94dc': '<$>{break}<$>',
    '94da': '<$>{break}<$>',
    '135b': '<$>{break}<$>',
    '135e': '<$>{break}<$>',
    '135d': '<$>{break}<$>',
    '1370': '<$>{break}<$>',
    '9240': '<$>{break}<$>',
    '13e9': '<$>{break}<$>',
    '1375': '<$>{break}<$>',
    '1679': '<$>{break}<$>',
    '1358': '<$>{break}<$>',
    '1352': '<$>{break}<$>',
    '1351': '<$>{break}<$>',
    '1376': '<$>{break}<$>',
    '1357': '<$>{break}<$>',
    '1354': '<$>{break}<$>',
    '1379': '<$>{break}<$>',
    '94d9': '<$>{break}<$>',
    '94d6': '<$>{break}<$>',
    '94d5': '<$>{break}<$>',
    '15462': '<$>{break}<$>',
    '94d3': '<$>{break}<$>',
    '94d0': '<$>{break}<$>',
    '13e0': '<$>{break}<$>',
    '13e6': '<$>{break}<$>',
    '976b': '<$>{break}<$>',
    '15c4': '<$>{break}<$>',
    '15c2': '<$>{break}<$>',
    '15c1': '<$>{break}<$>',
    '976e': '<$>{break}<$>{italic}<$>',
    '134c': '<$>{break}<$>',
    '15c8': '<$>{break}<$>',
    '92c8': '<$>{break}<$>',
    '16e9': '<$>{break}<$>',
    '16e3': '<$>{break}<$>',
    '16e0': '<$>{break}<$>',
    '16e6': '<$>{break}<$>',
    '16e5': '<$>{break}<$>',
    '91e5': '<$>{break}<$>',
    '91e6': '<$>{break}<$>',
    '91e0': '<$>{break}<$>',
    '91e3': '<$>{break}<$>',
    '13c4': '<$>{break}<$>',
    '13c7': '<$>{break}<$>',
    '91e9': '<$>{break}<$>',
    '13c2': '<$>{break}<$>',
    '9762': '<$>{break}<$>',
    '15ce': '<$>{break}<$>{italic}<$>',
    '9761': '<$>{break}<$>',
    '15cb': '<$>{break}<$>',
    '9764': '<$>{break}<$>',
    '9768': '<$>{break}<$>',
    '91ef': '<$>{break}<$>{italic}<$>',
    '91ea': '<$>{break}<$>',
    '91ec': '<$>{break}<$>',
    '13ce': '<$>{break}<$>{italic}<$>',
    '13cd': '<$>{break}<$>',
    '97da': '<$>{break}<$>',
    '13cb': '<$>{break}<$>',
    '13462': '<$>{break}<$>',
    '16ec': '<$>{break}<$>',
    '16ea': '<$>{break}<$>',
    '16ef': '<$>{break}<$>{italic}<$>',
    '97c1': '<$>{break}<$>',
    '97c2': '<$>{break}<$>',
    '97c4': '<$>{break}<$>',
    '97c7': '<$>{break}<$>',
    '92cd': '<$>{break}<$>',
    '92ce': '<$>{break}<$>{italic}<$>',
    '92cb': '<$>{break}<$>',
    '92da': '<$>{break}<$>',
    '92dc': '<$>{break}<$>',
    '92df': '<$>{break}<$>',
    '97df': '<$>{break}<$>',
    '155b': '<$>{break}<$>',
    '155e': '<$>{break}<$>',
    '155d': '<$>{break}<$>',
    '97dc': '<$>{break}<$>',
    '1675': '<$>{break}<$>',
    '1676': '<$>{break}<$>',
    '1670': '<$>{break}<$>',
    '1673': '<$>{break}<$>',
    '16462': '<$>{break}<$>',
    '97cb': '<$>{break}<$>',
    '97ce': '<$>{break}<$>{italic}<$>',
    '97cd': '<$>{break}<$>',
    '92c4': '<$>{break}<$>',
    '92c7': '<$>{break}<$>',
    '92c1': '<$>{break}<$>',
    '92c2': '<$>{break}<$>',
    '1551': '<$>{break}<$>',
    '97d5': '<$>{break}<$>',
    '97d6': '<$>{break}<$>',
    '1552': '<$>{break}<$>',
    '97d0': '<$>{break}<$>',
    '1554': '<$>{break}<$>',
    '1557': '<$>{break}<$>',
    '97d3': '<$>{break}<$>',
    '1558': '<$>{break}<$>',
    '167f': '<$>{break}<$>',
    '137f': '<$>{break}<$>',
    '167a': '<$>{break}<$>',
    '92d9': '<$>{break}<$>',
    '92d0': '<$>{break}<$>',
    '92d3': '<$>{break}<$>',
    '92d5': '<$>{break}<$>',
    '92d6': '<$>{break}<$>',
    '10dc': '<$>{break}<$>',
    '9262': '<$>{break}<$>',
    '9261': '<$>{break}<$>',
    '91f8': '<$>{break}<$>',
    '10df': '<$>{break}<$>',
    '9264': '<$>{break}<$>',
    '91f4': '<$>{break}<$>',
    '91f7': '<$>{break}<$>',
    '91f1': '<$>{break}<$>',
    '91f2': '<$>{break}<$>',
    '97d9': '<$>{break}<$>',
    '9149': '<$>{break}<$>',
    '9143': '<$>{break}<$>',
    '9140': '<$>{break}<$>',
    '9146': '<$>{break}<$>',
    '9145': '<$>{break}<$>',
    '9464': '<$>{break}<$>',
    '9467': '<$>{break}<$>',
    '9461': '<$>{break}<$>',
    '9462': '<$>{break}<$>',
    '9468': '<$>{break}<$>',
    '914c': '<$>{break}<$>',
    '914a': '<$>{break}<$>',
    '914f': '<$>{break}<$>{italic}<$>',
    '10d3': '<$>{break}<$>',
    '926b': '<$>{break}<$>',
    '10d0': '<$>{break}<$>',
    '10d6': '<$>{break}<$>',
    '926e': '<$>{break}<$>{italic}<$>',
    '926d': '<$>{break}<$>',
    '91fd': '<$>{break}<$>',
    '91fe': '<$>{break}<$>',
    '10d9': '<$>{break}<$>',
    '91fb': '<$>{break}<$>',
    '91fc': '<$>{break}<$>',
    '946e': '<$>{break}<$>{italic}<$>',
    '946d': '<$>{break}<$>',
    '946b': '<$>{break}<$>',
    '10da': '<$>{break}<$>',
    '10d5': '<$>{break}<$>',
    '9267': '<$>{break}<$>',
    '9268': '<$>{break}<$>',
    '16df': '<$>{break}<$>',
    '16da': '<$>{break}<$>',
    '16dc': '<$>{break}<$>',
    '9454': '<$>{break}<$>',
    '9457': '<$>{break}<$>',
    '9451': '<$>{break}<$>',
    '9452': '<$>{break}<$>',
    '136d': '<$>{break}<$>',
    '136e': '<$>{break}<$>{italic}<$>',
    '136b': '<$>{break}<$>',
    '13d9': '<$>{break}<$>',
    '13da': '<$>{break}<$>',
    '13dc': '<$>{break}<$>',
    '13df': '<$>{break}<$>',
    '1568': '<$>{break}<$>',
    '1561': '<$>{break}<$>',
    '1564': '<$>{break}<$>',
    '1567': '<$>{break}<$>',
    '16d5': '<$>{break}<$>',
    '16d6': '<$>{break}<$>',
    '16d0': '<$>{break}<$>',
    '16d3': '<$>{break}<$>',
    '945d': '<$>{break}<$>',
    '945e': '<$>{break}<$>',
    '16d9': '<$>{break}<$>',
    '945b': '<$>{break}<$>',
    '156b': '<$>{break}<$>',
    '156d': '<$>{break}<$>',
    '156e': '<$>{break}<$>{italic}<$>',
    '105b': '<$>{break}<$>',
    '1364': '<$>{break}<$>',
    '1368': '<$>{break}<$>',
    '1361': '<$>{break}<$>',
    '13d0': '<$>{break}<$>',
    '13d3': '<$>{break}<$>',
    '13d5': '<$>{break}<$>',
    '13d6': '<$>{break}<$>',
    '97a1': '',
    '97a2': '',
    '9723': '',
    '94a1': '',
    '94a4': '',
    '94ad': '',
    '1020': '',
    '10a1': '',
    '10a2': '',
    '1023': '',
    '10a4': '',
    '1025': '',
    '1026': '',
    '10a7': '',
    '10a8': '',
    '1029': '',
    '102a': '',
    '10ab': '',
    '102c': '',
    '10ad': '',
    '10ae': '',
    '102f': '',
    '97ad': '',
    '97a4': '',
    '9725': '',
    '9726': '',
    '97a7': '',
    '97a8': '',
    '9729': '',
    '972a': '',
    '9120': '<$>{end-italic}<$>',
    '91a1': '',
    '91a2': '',
    '9123': '',
    '91a4': '',
    '9125': '',
    '9126': '',
    '91a7': '',
    '91a8': '',
    '9129': '',
    '912a': '',
    '91ab': '',
    '912c': '',
    '91ad': '',
    '97ae': '',
    '972f': '',
    '91ae': '<$>{italic}<$>',
    '912f': '<$>{italic}<$>',
    '94a8': '',
    '9423': '',
    '94a2': '',
}


CHARACTERS = {
    '20': ' ',
    'a1': '!',
    'a2': '"',
    '23': '#',
    'a4': '$',
    '25': '%',
    '26': '&',
    'a7': '\'',
    'a8': '(',
    '29': ')',
    '2a': 'á',
    'ab': '+',
    '2c': ',',
    'ad': '-',
    'ae': '.',
    '2f': '/',
    'b0': '0',
    '31': '1',
    '32': '2',
    'b3': '3',
    '34': '4',
    'b5': '5',
    'b6': '6',
    '37': '7',
    '38': '8',
    'b9': '9',
    'ba': ':',
    '3b': ';',
    'bc': '<',
    '3d': '=',
    '3e': '>',
    'bf': '?',
    '40': '@',
    'c1': 'A',
    'c2': 'B',
    '43': 'C',
    'c4': 'D',
    '45': 'E',
    '46': 'F',
    'c7': 'G',
    'c8': 'H',
    '49': 'I',
    '4a': 'J',
    'cb': 'K',
    '4c': 'L',
    'cd': 'M',
    'ce': 'N',
    '4f': 'O',
    'd0': 'P',
    '51': 'Q',
    '52': 'R',
    'd3': 'S',
    '54': 'T',
    'd5': 'U',
    'd6': 'V',
    '57': 'W',
    '58': 'X',
    'd9': 'Y',
    'da': 'Z',
    '5b': '[',
    'dc': 'é',
    '5d': ']',
    '5e': 'í',
    'df': 'ó',
    'e0': 'ú',
    '61': 'a',
    '62': 'b',
    'e3': 'c',
    '64': 'd',
    'e5': 'e',
    'e6': 'f',
    '67': 'g',
    '68': 'h',
    'e9': 'i',
    'ea': 'j',
    '6b': 'k',
    'ec': 'l',
    '6d': 'm',
    '6e': 'n',
    'ef': 'o',
    '70': 'p',
    'f1': 'q',
    'f2': 'r',
    '73': 's',
    'f4': 't',
    '75': 'u',
    '76': 'v',
    'f7': 'w',
    'f8': 'x',
    '79': 'y',
    '7a': 'z',
    'fb': 'ç',
    '7c': '÷',
    'fd': 'Ñ',
    'fe': 'ñ',
    '7f': '',
    '80': ''
}


SPECIAL_CHARS = {
    '91b0': '®',
    '9131': '°',
    '9132': '½',
    '91b3': '¿',
    '91b4': '™',
    '91b5': '¢',
    '91b6': '£',
    '9137': '♪',
    '9138': 'à',
    '91b9': ' ',
    '91ba': 'è',
    '913b': 'â',
    '91bc': 'ê',
    '913d': 'î',
    '913e': 'ô',
    '91bf': 'û'
}


EXTENDED_CHARS = {
    '9220': 'Á',
    '92a1': 'É',
    '92a2': 'Ó',
    '9223': 'Ú',
    '92a4': 'Ü',
    '9225': 'ü',
    '9226': '‘',
    '92a7': '¡',
    '92a8': '*',
    '9229': '’',
    '922a': '—',
    '92ab': '©',
    '922c': '℠',
    '92ad': '•',
    '92ae': '“',
    '922f': '”',
    '92b0': 'À',
    '9231': 'Â',
    '9232': 'Ç',
    '92b3': 'È',
    '9234': 'Ê',
    '92b5': 'Ë',
    '92b6': 'ë',
    '9237': 'Î',
    '9238': 'Ï',
    '92b9': 'ï',
    '92ba': 'Ô',
    '923b': 'Ù',
    '92bc': 'ù',
    '923d': 'Û',
    '923e': '«',
    '92bf': '»',
    '1320': 'Ã',
    '13a1': 'ã',
    '13a2': 'Í',
    '1323': 'Ì',
    '13a4': 'ì',
    '1325': 'Ò',
    '1326': 'ò',
    '13a7': 'Õ',
    '13a8': 'õ',
    '1329': '{',
    '132a': '}',
    '13ab': '\\',
    '132c': '^',
    '13ad': '_',
    '13ae': '¦',
    '132f': '~',
    '13b0': 'Ä',
    '1331': 'ä',
    '1332': 'Ö',
    '13b3': 'ö',
    '1334': 'ß',
    '13b5': '¥',
    '13b6': '¤',
    '1337': '|',
    '1338': 'Å',
    '13b9': 'å',
    '13ba': 'Ø',
    '133b': 'ø',
    '13bc': '┌',
    '133d': '┐',
    '133e': '└',
    '13bf': '┘',
}


# Cursor positioning codes
PAC_HIGH_BYTE_BY_ROW = [
    'xx',
    '91',
    '91',
    '92',
    '92',
    '15',
    '15',
    '16',
    '16',
    '97',
    '97',
    '10',
    '13',
    '13',
    '94',
    '94'
]
PAC_LOW_BYTE_BY_ROW_RESTRICTED = [
    'xx',
    'd0',
    '70',
    'd0',
    '70',
    'd0',
    '70',
    'd0',
    '70',
    'd0',
    '70',
    'd0',
    'd0',
    '70',
    'd0',
    '70'
]

# High order bytes come first, then each key contains a list of low bytes.
# Any of the values in that list, coupled with the high order byte will
# map to the (row, column) tuple.
# This particular dictionary will get transformed to a more suitable form for
# usage like PAC_BYTES_TO_POSITIONING_MAP[u'91'][u'd6'] = (1, 12)
PAC_BYTES_TO_POSITIONING_MAP = {
    '91': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (1, 0),  # noqa
        ('70', 'f1', '62', 'e3', '64', 'e5', 'e6', '67', '68', 'e9', 'ea', '6b', 'ec', '6d'): (2, 0),  # noqa
        ('52', 'd3'): (1, 4),
        ('54', 'd5'): (1, 8),
        ('d6', '57'): (1, 12),
        ('58', 'd9'): (1, 16),
        ('da', '5b'): (1, 20),
        ('dc', '5d'): (1, 24),
        ('5e', 'df'): (1, 28),

        ('f2', '73'): (2, 4),
        ('f4', '75'): (2, 8),
        ('76', 'f7'): (2, 12),
        ('f8', '79'): (2, 16),
        ('7a', 'fb'): (2, 20),
        ('7c', 'fd'): (2, 24),
        ('fe', '7f'): (2, 28)
    },
    '92': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (3, 0),  # noqa
        ('70', 'f1', '62', 'e3', '64', 'e5', 'e6', '67', '68', 'e9', 'ea', '6b', 'ec', '6d'): (4, 0),  # noqa
        ('52', 'd3'): (3, 4),
        ('54', 'd5'): (3, 8),
        ('d6', '57'): (3, 12),
        ('58', 'd9'): (3, 16),
        ('da', '5b'): (3, 20),
        ('dc', '5d'): (3, 24),
        ('5e', 'df'): (3, 28),

        ('f2', '73'): (4, 4),
        ('f4', '75'): (4, 8),
        ('76', 'f7'): (4, 12),
        ('f8', '79'): (4, 16),
        ('7a', 'fb'): (4, 20),
        ('7c', 'fd'): (4, 24),
        ('fe', '7f'): (4, 28)
    },
    '15': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (5, 0),  # noqa
        ('70', 'f1', '62', 'e3', '64', 'e5', 'e6', '67', '68', 'e9', 'ea', '6b', 'ec', '6d'): (6, 0),  # noqa
        ('52', 'd3'): (5, 4),
        ('54', 'd5'): (5, 8),
        ('d6', '57'): (5, 12),
        ('58', 'd9'): (5, 16),
        ('da', '5b'): (5, 20),
        ('dc', '5d'): (5, 24),
        ('5e', 'df'): (5, 28),

        ('f2', '73'): (6, 4),
        ('f4', '75'): (6, 8),
        ('76', 'f7'): (6, 12),
        ('f8', '79'): (6, 16),
        ('7a', 'fb'): (6, 20),
        ('7c', 'fd'): (6, 24),
        ('fe', '7f'): (6, 28)
    },
    '16': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (7, 0),  # noqa
        ('70', 'f1', '62', 'e3', '64', 'e5', 'e6', '67', '68', 'e9', 'ea', '6b', 'ec', '6d'): (8, 0),  # noqa
        ('52', 'd3'): (7, 4),
        ('54', 'd5'): (7, 8),
        ('d6', '57'): (7, 12),
        ('58', 'd9'): (7, 16),
        ('da', '5b'): (7, 20),
        ('dc', '5d'): (7, 24),
        ('5e', 'df'): (7, 28),

        ('f2', '73'): (8, 4),
        ('f4', '75'): (8, 8),
        ('76', 'f7'): (8, 12),
        ('f8', '79'): (8, 16),
        ('7a', 'fb'): (8, 20),
        ('7c', 'fd'): (8, 24),
        ('fe', '7f'): (8, 28)
    },
    '97': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (9, 0),  # noqa
        ('70', 'f1', '62', 'e3', '64', 'e5', 'e6', '67', '68', 'e9', 'ea', '6b', 'ec', '6d'): (10, 0),  # noqa
        ('52', 'd3'): (9, 4),
        ('54', 'd5'): (9, 8),
        ('d6', '57'): (9, 12),
        ('58', 'd9'): (9, 16),
        ('da', '5b'): (9, 20),
        ('dc', '5d'): (9, 24),
        ('5e', 'df'): (9, 28),

        ('f2', '73'): (10, 4),
        ('f4', '75'): (10, 8),
        ('76', 'f7'): (10, 12),
        ('f8', '79'): (10, 16),
        ('7a', 'fb'): (10, 20),
        ('7c', 'fd'): (10, 24),
        ('fe', '7f'): (10, 28)
    },
    '10': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (11, 0),  # noqa
        ('52', 'd3'): (11, 4),
        ('54', 'd5'): (11, 8),
        ('d6', '57'): (11, 12),
        ('58', 'd9'): (11, 16),
        ('da', '5b'): (11, 20),
        ('dc', '5d'): (11, 24),
        ('5e', 'df'): (11, 28),
    },
    '13': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (12, 0),  # noqa
        ('70', 'f1', '62', 'e3', '64', 'e5', 'e6', '67', '68', 'e9', 'ea', '6b', 'ec', '6d'): (13, 0),  # noqa
        ('52', 'd3'): (12, 4),
        ('54', 'd5'): (12, 8),
        ('d6', '57'): (12, 12),
        ('58', 'd9'): (12, 16),
        ('da', '5b'): (12, 20),
        ('dc', '5d'): (12, 24),
        ('5e', 'df'): (12, 28),

        ('f2', '73'): (13, 4),
        ('f4', '75'): (13, 8),
        ('76', 'f7'): (13, 12),
        ('f8', '79'): (13, 16),
        ('7a', 'fb'): (13, 20),
        ('7c', 'fd'): (13, 24),
        ('fe', '7f'): (13, 28)
    },
    '94': {
        ('d0', '51', 'c2', '43', 'c4', '45', '46', 'c7', 'c8', '49', '4a', 'cb', '4c', 'cd'): (14, 0),  # noqa
        ('70', 'f1', '62', 'e3', '64', 'e5', 'e6', '67', '68', 'e9', 'ea', '6b', 'ec', '6d'): (15, 0),  # noqa
        ('52', 'd3'): (14, 4),
        ('54', 'd5'): (14, 8),
        ('d6', '57'): (14, 12),
        ('58', 'd9'): (14, 16),
        ('da', '5b'): (14, 20),
        ('dc', '5d'): (14, 24),
        ('5e', 'df'): (14, 28),

        ('f2', '73'): (15, 4),
        ('f4', '75'): (15, 8),
        ('76', 'f7'): (15, 12),
        ('f8', '79'): (15, 16),
        ('7a', 'fb'): (15, 20),
        ('7c', 'fd'): (15, 24),
        ('fe', '7f'): (15, 28)
    }
}


def _create_position_to_bytes_map(bytes_to_pos):
    result = {}
    for high_byte, low_byte_dict in list(bytes_to_pos.items()):

        # must contain mappings to column, to the tuple of possible values
        for low_byte_list in list(low_byte_dict.keys()):
            column = bytes_to_pos[high_byte][low_byte_list][1]

            row = bytes_to_pos[high_byte][low_byte_list][0]
            if row not in result:
                result[row] = {}

            result[row][column] = (
                tuple(product([high_byte], low_byte_list)))
    return result

# (Almost) the reverse of PAC_BYTES_TO_POSITIONING_MAP. Call with arguments
# like for example [15][4] to get the tuple ((u'94', u'f2'), (u'94', u'73'))
POSITIONING_TO_PAC_MAP = _create_position_to_bytes_map(
    PAC_BYTES_TO_POSITIONING_MAP
)


def _restructure_bytes_to_position_map(byte_to_pos_map):
    return {
        k_: {
            low_byte: byte_to_pos_map[k_][low_byte_list]
            for low_byte_list in list(v_.keys()) for low_byte in low_byte_list
        }
        for k_, v_ in list(byte_to_pos_map.items())
    }

# Now use the dict with arguments like [u'91'][u'75'] directly.
PAC_BYTES_TO_POSITIONING_MAP = _restructure_bytes_to_position_map(
    PAC_BYTES_TO_POSITIONING_MAP)


# Inverted character lookup
CHARACTER_TO_CODE = {
    character: code
    for code, character in viewitems(CHARACTERS)
}

SPECIAL_OR_EXTENDED_CHAR_TO_CODE = {
    character: code for code, character in viewitems(EXTENDED_CHARS)
}
SPECIAL_OR_EXTENDED_CHAR_TO_CODE.update(
    {character: code for code, character in viewitems(SPECIAL_CHARS)}
)

# Time to transmit a single codeword = 1 second / 29.97
MICROSECONDS_PER_CODEWORD = 1000.0 * 1000.0 / (30.0 * 1000.0 / 1001.0)


HEADER = 'Scenarist_SCC V1.0'
