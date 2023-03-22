import PySimpleGUI as sg
import os
import xml.etree.ElementTree as ET
from pathlib import Path

def compareResults(xmlFolderPath, logFileFlagEnable, logFileFlagDisable, vType):
    result=""
    vulnerabilityMapTP=set()
    vulnerabilityMapTN=set()
    vulnerabilityMap=set()
    for filename in os.listdir(xmlFolderPath):
        if not filename.endswith('.xml'): continue
        fullname = os.path.join(xmlFolderPath, filename)
        tree = ET.parse(fullname)
        filename=filename.rstrip(".xml")
        vulnerability=tree.find("vulnerability").text
        category=tree.find("category").text
        vulnerabilityMap.add(filename)
        if(category.lower()==vType or vType=='All'):
            if(vulnerability.lower() == "true"):
                vulnerabilityMapTP.add(filename)
            else:
                vulnerabilityMapTN.add(filename)

    result+="\n\n-----------------BenchmarkJava-----------------\n\n"
    result+="Total True Positives: "+ str(len(vulnerabilityMapTP))+"\n"
    result+="Total True Negatives: "+ str(len(vulnerabilityMapTN))+"\n"

    vulnerabilityMapFlagEnable=set()
    with open(logFileFlagEnable,'r') as file:
        for line in file:
            for word in line.split():
                if(".java" in word):
                    word=word.split(".java", 1)[0]
                    filename=Path(word).name
                    vulnerabilityMapFlagEnable.add(filename)

    result+="\n\n-----------------FLAG ENABLED-----------------\n\n"
    result+="Total True Positives: "+ str(len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagEnable)))+"\n"
    result+="Total False Positives: "+ str(len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagEnable)))+"\n"
    result+="Total True Negatives: "+ str(len(vulnerabilityMapTN)-len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagEnable)))+"\n"
    result+="Total False Negatives: "+ str(len(vulnerabilityMapTP)-len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagEnable)))+"\n"

    vulnerabilityMapFlagDisable=set()
    with open(logFileFlagDisable,'r') as file:
        for line in file:
            for word in line.split():
                if(".java" in word):
                    word=word.split(".java", 1)[0]
                    filename=Path(word).name
                    vulnerabilityMapFlagDisable.add(filename)

    result+="\n\n-----------------FLAG DISABLED-----------------\n\n"
    result+="Total True Positives: "+ str(len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagDisable)))+"\n"
    result+="Total False Positives: "+ str(len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagDisable)))+"\n"
    result+="Total True Negatives: "+ str(len(vulnerabilityMapTN)-len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagDisable)))+"\n"
    result+="Total False Negatives: "+ str(len(vulnerabilityMapTP)-len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagDisable)))+"\n"
    print(result+"\n\n")


    print("\n\n True Negatives Flag Enabled:\n")
    print(vulnerabilityMapTN.difference(vulnerabilityMapFlagEnable))

    print("\n\n True Negatives Flag Disabled:\n")
    print(vulnerabilityMapTN.difference(vulnerabilityMapFlagDisable))
    return result;



xmlFolder=""
flagEnabledLogs=""
flagDisabledLogs=""
vulnerabilityType=""
sg.theme('DarkAmber')   # Add a touch of color
# All the stuff inside your window.
layout = [  [sg.Text("Select BenchmarkJava XML: ",size=(27, 1)), sg.Input(size=(40, 1)), sg.FolderBrowse(key="-XMLFOLDER-",size=(5, 1))],
            [sg.Text("Choose Logs with Flag Enabled: ",size=(27, 1)), sg.Input(size=(40, 1)), sg.FileBrowse(key="-FLAGENABLEDLOG-",size=(5, 1))],
            [sg.Text("Choose Logs with Flag Disabled: ",size=(27, 1)), sg.Input(size=(40, 1)), sg.FileBrowse(key="-FLAGDISABLEDLOG-",size=(5, 1))],
            [sg.Text("Vulnerability Type: ",size=(30, 1)), sg.Combo(["All","cmdi","sqli","crypto","hash","ldapi","pathtraver","securecookie","sqli","trustbound",
            "weakrand","xpathi","xss"],default_value='All',key='-VTYPE-',size=(20, 1))],
            [sg.Button('Compare'), sg.Button('Cancel')] ]

# Create the Window
window = sg.Window('BenchmarkJava Analyzer', layout, element_justification='c')
# Event Loop to process "events" and get the "values" of the inputs
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel': # if user closes window or clicks cancel
        break
    elif event == 'Compare':
        xmlFolder=values[0]
        if(xmlFolder=="" or os.path.exists(xmlFolder)==False):
            sg.Popup('xmlPATH: '+ str(xmlFolder)+' Please select valid xml path ' + str(os.path.exists(xmlFolder)))
            continue
        flagEnabledLogs=values[1]
        if(flagEnabledLogs=="" or os.path.isfile(flagEnabledLogs)==False):
            sg.Popup('Please select valid Flag Enabled Logs')
            continue
        flagDisabledLogs=values[2]
        if(flagDisabledLogs=="" or os.path.isfile(flagDisabledLogs)==False):
            sg.Popup('Please select valid Flag Disabled Logs')
            continue
        vulnerabilityType=values['-VTYPE-']
        sg.Popup(compareResults(xmlFolder, flagEnabledLogs, flagDisabledLogs, vulnerabilityType), title="Results")
        # sg.Popup("XML FOLDER: "+ xmlFolder
        # +"\n"+ "FLAG ENABLED LOG: "+flagEnabledLogs
        # +"\n"+ "FLAG DISABLED LOG: "+flagDisabledLogs)


window.close()
