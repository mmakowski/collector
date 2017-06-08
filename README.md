Bugs And Vulnerabilities project
===============================

Collector module
--------------

This maven module aim at creating datasets of vulnerable and/or buggy Files as well as clear files given a git repository

### Requirements
Please put the CVE XML in the resource folder (available at [this link](https://nvd.nist.gov/download.cfm) )

The model and utils modules of the project are also required

### Content

 + DataCollector Main class containing everything require to build a set
 + buggy clear vulnerable are package containing the function required to build the dataset
 + collector.properties contains all properties that can be modified before each run
    * nbThreads: (number of thread that multithreading function should use)
    * software: (software under study)
    * yearBeginning: first year to study (min 2002)
    * yearEnd: last year under consideration
    * softwareGit: regexp of the git repo of the software
    * extension: regexp to filter file according the language
    * bugTracker: name of the bugtracker
    * bugShare: how many bugs for the realistic settings
    * clearShare: how many clear per vulnerable files for the realistic setting
    * cveOnly: should we only work on cve or count commit mentionnning vulnerability
    * experimentalgen: generate the experimental dataset
    * realisticgen: generate the realistic dataset
    
    
   
### Tests 

This module contains test only for the cve parser, the other part are just generation of the dataset

### Note

As other part of the project, this module is coded in Kotlin 1.0.4 and use Speck as a testing framework

Matthieu Jimenez - 2016
                                                            
