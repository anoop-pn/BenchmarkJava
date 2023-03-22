import xml.etree.ElementTree as ET
from pathlib import Path
import os

xmlFolderPath = '/home/anooppn/TaintChecker/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode'
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
    if(category.lower()=="cmdi"):
        if(vulnerability.lower() == "true"):
    	    vulnerabilityMapTP.add(filename)
        else:
    	    vulnerabilityMapTN.add(filename)

print("\n\n--------------------------BenchmarkJava------------------------------")
print("Total True Positives: "+ str(len(vulnerabilityMapTP))+"\n")
print("Total True Negatives: "+ str(len(vulnerabilityMapTN))+"\n")

logFileFlagEnable= '/home/anooppn/BenchmarkJavaReport_polytnt_WithStub_FE.txt'
vulnerabilityMapFlagEnable=set()
with open(logFileFlagEnable,'r') as file:
    for line in file:
        for word in line.split():
    	    if(".java" in word):
                word=word.split(".java", 1)[0]
                filename=Path(word).name
                vulnerabilityMapFlagEnable.add(filename)

print("\n\n--------------------------FLAG ENABLED------------------------------")
print("Total True Positives: "+ str(len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagEnable)))+"\n")
print("Total False Positives: "+ str(len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagEnable)))+"\n")
print("Total True Negatives: "+ str(len(vulnerabilityMapTN)-len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagEnable)))+"\n")
print("Total False Negatives: "+ str(len(vulnerabilityMapTP)-len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagEnable)))+"\n")

logFileFlagDisable= '/home/anooppn/BenchmarkJavaReport_polytnt_WithStub_FD.txt'
vulnerabilityMapFlagDisable=set()
with open(logFileFlagDisable,'r') as file:
    for line in file:
        for word in line.split():
    	    if(".java" in word):
                word=word.split(".java", 1)[0]
                filename=Path(word).name
                vulnerabilityMapFlagDisable.add(filename)

print("\n\n--------------------------FLAG DISABLED------------------------------")
print("Total True Positives: "+ str(len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagDisable)))+"\n")
print("Total False Positives: "+ str(len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagDisable)))+"\n")
print("Total True Negatives: "+ str(len(vulnerabilityMapTN)-len(vulnerabilityMapTN.intersection(vulnerabilityMapFlagDisable)))+"\n")
print("Total False Negatives: "+ str(len(vulnerabilityMapTP)-len(vulnerabilityMapTP.intersection(vulnerabilityMapFlagDisable)))+"\n")
