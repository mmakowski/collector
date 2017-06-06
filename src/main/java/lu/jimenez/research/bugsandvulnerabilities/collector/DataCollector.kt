/////////////////////////////////////////////////////////////////////////////////////////
//                 University of Luxembourg  -
//                 Interdisciplinary center for Security and Trust (SnT)
//                 Copyright © 2016 University of Luxembourg, SnT
//
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 3 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
//
//
//    Author: Matthieu Jimenez – SnT – matthieu.jimenez@uni.lu
//
//////////////////////////////////////////////////////////////////////////////////////////
package lu.jimenez.research.bugsandvulnerabilities.collector

import lu.jimenez.research.bugsandvulnerabilities.collector.buggy.BugSet
import lu.jimenez.research.bugsandvulnerabilities.collector.clear.ClearSet
import lu.jimenez.research.bugsandvulnerabilities.collector.utils.Constants
import lu.jimenez.research.bugsandvulnerabilities.collector.vulnerable.VulnerabilitySet
import lu.jimenez.research.bugsandvulnerabilities.model.BuggyFile
import lu.jimenez.research.bugsandvulnerabilities.model.VulnerableFile
import lu.jimenez.research.bugsandvulnerabilities.model.extension.UtilitaryMethods
import lu.jimenez.research.bugsandvulnerabilities.model.internal.Document
import lu.jimenez.research.bugsandvulnerabilities.model.internal.DocumentType
import lu.jimenez.research.bugsandvulnerabilities.utils.Serialization
import java.util.*

/**
 * Data Collector class gather everything needed to build the dataset
 */
class DataCollector(val repositoryPath: String, val savingFolder: String) {

    /**
     * Generating the Vulnerable Set, it's the same for Accurate and Realistic
     *
     * @return list of [VulnerableFile]
     */
    fun generatingVulnerableSet(): List<VulnerableFile> {
        val vsc: VulnerabilitySet = VulnerabilitySet(repositoryPath)

        var mapofCommit = vsc.populateWithCVEDatabaseInfo()
        mapofCommit = vsc.populateWithCVEPresentInCommit(mapofCommit)
        var listOfcommit: List<String?>? = null

        //only consider vulnerability with CVE-Number ?
        if (!Constants.CVE_ONLY) {
            listOfcommit = vsc.populateWithCommitContainingKeyword(mapofCommit)
        }
        val listOfVulnerability = vsc.creatingVulnerableDataset(mapofCommit, listOfcommit)
        Serialization.saveListData(listOfVulnerability, savingFolder + "Vulnset.obj")
        return listOfVulnerability
    }

    /**
     * Generating the Bug set comming from either bugtracker or keyword
     *
     * @param listOfVulnerableCommit list of commit already refer as vulnerable patch
     * @param bugTracker should use bug tracker as a way or keyword
     *
     * @return list of [BuggyFile]
     */
    fun generateBuggySet(listOfVulnerableCommit: Map<String, Int>? = null, bugTracker: Boolean): List<BuggyFile> {
        val brs = BugSet(repositoryPath)
        val listOfCommit = brs.populatewithBug(listOfVulnerableCommit?.keys?.toList(),bugTracker)?: return listOf()
        val listOfBugs = brs.createBuggyDataset(listOfCommit)
        val name:String
        if (bugTracker) name = "BugReportSet"
        else name = "BugKeywordSet"
        Serialization.saveListData(listOfBugs, savingFolder + "$name.obj")
        return listOfBugs
    }

    /**
     * Generating a set of files that have an history of being buggy at the time where the vulnerability was patched
     *
     * @param listOfVulnerableCommit
     * @param listOfVulnerableFiles
     *
     * @return list of [Document]
     */
    fun generateBuggyFromVulnerabilityTime(listOfVulnerableFiles: Set<String>, listOfVulnerableCommit: Map<String,Int>): Pair<Set<String>, List<Document>> {
        val bhs = BugSet(repositoryPath)
        println("plouf1")
        val listOfCommit = bhs.populatewithBug(listOfVulnerableCommit.keys.toList(),false)
        println("plouf2")
        val setOfBugFiles = bhs.setOfBugFiles(listOfCommit,listOfVulnerableFiles)
        println("plouf3")
        val listOfBugs = bhs.createFilesHistoricallyBuggyDataset(listOfVulnerableCommit,setOfBugFiles)
        //Serialization.saveListData(listOfBugs, savingFolder + "${extraPath}bug.obj")
        return Pair(setOfBugFiles,listOfBugs)
    }

    /**
     * Method to generate a clear set given a list of files to exclude and a list of commits to work
     */
    fun generateClearSet(ListOfAlreadyUsedFiles: Set<String>, listOfCommitToWorkOn: Map<String,Int>, numberOfIteration: Int): List<Document> {
        val cs = ClearSet(repositoryPath)
        val listOfClearFiles = cs.setOfClearFile(ListOfAlreadyUsedFiles)
        val listOfClear = cs.createClearSet(listOfCommitToWorkOn,listOfClearFiles, numberOfIteration)
        //Serialization.saveListData(listOfClear, savingFolder + "${extraPath}clear.obj")
        return listOfClear
    }

    /**
     * Method generating the Exeprimental setting dataset
     */
    fun generateExperimentalVulnerableSet(listOfVulnerableFiles: List<VulnerableFile>, addingClearFile: Boolean, extraPath: String){
        //Retrieving Vulnerability List
        val listOfCommit = UtilitaryMethods.setOfCommitPatchVulnerability(listOfVulnerableFiles)

        //Generate Buggy Set
        val listOfBug = generateBuggySet(listOfCommit,true)
        val setOfAlreadyUsedFile = UtilitaryMethods.setOfAlreadyPresentFiles(listOfVulnerableFiles, listOfBug)
        val listOfClear: List<Document>?
        if(addingClearFile){
            listOfClear = generateClearSet(setOfAlreadyUsedFile,listOfCommit,1)
        }
        else listOfClear=null

        //Transforming it into Hashmap
        val mapOfIDDoc: MutableMap<Int, Document> = mutableMapOf()
        val mapOfIDCat: MutableMap<Int, DocumentType> = mutableMapOf()

        //Extracting intel of vulnerabilities
        for (vuln in listOfVulnerableFiles) {
            val hashold = vuln.vulnerableFile.hashCode()
            val hashnew = vuln.patchedFile.hashCode()
            mapOfIDCat.put(hashold, DocumentType.VULNERABLE_FILE)
            mapOfIDCat.put(hashnew, DocumentType.PATCHED_VULNERABLE_FILE)
            mapOfIDDoc.put(hashold, vuln.vulnerableFile)
            mapOfIDDoc.put(hashnew, vuln.patchedFile)
        }
        //Extracting intel of buggy
        for (bug in listOfBug) {
            val hashold = bug.buggyFile.hashCode()
            val hashnew = bug.patchedFile.hashCode()
            mapOfIDCat.put(hashold, DocumentType.BUGGY_FILE)
            mapOfIDCat.put(hashnew, DocumentType.PATCHED_BUGGY_FILE)
            mapOfIDDoc.put(hashold, bug.buggyFile)
            mapOfIDDoc.put(hashnew, bug.patchedFile)
        }
        //Extracting intel of clear
        if(listOfClear != null)
        for (clear in listOfClear) {
            val hash = clear.hashCode()
            mapOfIDCat.put(hash, DocumentType.CLEAR_FILE)
            mapOfIDDoc.put(hash, clear)
        }

        Serialization.saveMapHashData(mapOfIDCat,savingFolder+"${extraPath}experimental_MapOfIdCat.obj")
        Serialization.saveMapHashData(mapOfIDDoc,savingFolder+"${extraPath}experimental_MapOfIdDoc.obj")
    }

    /**
     * Method to generate a set corresponding to the realistic setting experiment
     *
     * @param listOfVulnerableFiles
     */
    fun generateRealisticVulnerableSet(listOfVulnerableFiles: List<VulnerableFile>, extraPath: String){

        //Processing Vulnerable
        val listOfCommit = UtilitaryMethods.setOfCommitPatchVulnerability(listOfVulnerableFiles)
        val setOfVulnerable = UtilitaryMethods.setOfAlreadyPresentFiles(listOfVulnerableFiles)

        println("vuln ok")

        //Generating Buggy set
        val buggyset = generateBuggyFromVulnerabilityTime(setOfVulnerable,listOfCommit)
        val listOfBuggy: List<Document> = buggyset.second
        val setOfAlreadyUsedFiles = (buggyset.first as MutableSet)
        setOfAlreadyUsedFiles.addAll(setOfVulnerable)

        println("bug ok")
        //Generating clear set
        val listOfClear: List<Document> = generateClearSet(setOfAlreadyUsedFiles,listOfCommit,Constants.CLEAR_SHARE)
        println("clear ok")
        //Transforming it into Hashmap
        val mapOfIDDoc: MutableMap<Int, Document> = mutableMapOf()
        val mapOfIDCat: MutableMap<Int, DocumentType> = mutableMapOf()

        //Extracting intel of vulnerabilities
        for (vuln in listOfVulnerableFiles) {
            val hashold = vuln.vulnerableFile.hashCode()
            val hashnew = vuln.patchedFile.hashCode()
            mapOfIDCat.put(hashold, DocumentType.VULNERABLE_FILE)
            mapOfIDCat.put(hashnew, DocumentType.PATCHED_VULNERABLE_FILE)
            mapOfIDDoc.put(hashold, vuln.vulnerableFile)
            mapOfIDDoc.put(hashnew, vuln.patchedFile)
        }
        //Extracting intel of buggy
        for (bug in listOfBuggy) {
            val hash = bug.hashCode()
            mapOfIDCat.put(hash, DocumentType.BUGGY_FILE)
            mapOfIDDoc.put(hash, bug)
        }
        //Extracting intel of clear
        for (clear in listOfClear) {
            val hash = clear.hashCode()
            mapOfIDCat.put(hash, DocumentType.CLEAR_FILE)
            mapOfIDDoc.put(hash, clear)
        }
        Serialization.saveMapHashData(mapOfIDCat,savingFolder+"${extraPath}real_MapOfIdCat.obj")
        Serialization.saveMapHashData(mapOfIDDoc,savingFolder+"${extraPath}real_MapOfIdDoc.obj")
    }


    companion object run {
        /**
         * Main method launching the gathering process
         */
        @JvmStatic
        fun main(args: Array<String>) {
            if (args.size > 0 && args.size < 3) {
                val repositoryPath = args[0]
                val savingFolder: String
                if (args.size == 2)
                    savingFolder = args[1]
                else savingFolder = this.javaClass.classLoader.getResource("").path + "saving/"

                loadingProperties()

                //Creation of the class
                val dataCollector = DataCollector(repositoryPath, savingFolder)
                val listOfVulnerable = dataCollector.generatingVulnerableSet()

                if(Constants.EXPERIMENTAL_GEN){
                    dataCollector.generateExperimentalVulnerableSet(listOfVulnerable,false,"")
                }
                if(Constants.REALISTIC_GEN)
                    dataCollector.generateRealisticVulnerableSet(listOfVulnerable,"")

            } else {
                println("Incorrect number of Arguments! \n Should be 1 or 2 arguments")
                return
            }

        }

        /**
         * Method for loading properties located in the collector.properties file
         */
        fun loadingProperties() {
            val inputStream = this.javaClass.classLoader.getResourceAsStream("collector.properties")

            val properties = Properties()
            properties.load(inputStream)
            inputStream.close()
            Constants.NB_THREAD = properties.getProperty("nbThreads").toInt()
            Constants.SOFTWARE = properties.getProperty("software")
            Constants.YEAR_BEGINNING = properties.getProperty("yearBeginning").toInt()
            Constants.YEAR_END = properties.getProperty("yearEnd").toInt()
            Constants.SOFTWARE_GIT = properties.getProperty("softwareGit")
            Constants.FILE_EXTENSION = properties.getProperty("extension")
            Constants.BUG_TRACKER = properties.getProperty("bugTracker")
            Constants.BUG_SHARE = properties.getProperty("bugShare").toInt()
            Constants.CLEAR_SHARE = properties.getProperty("clearShare").toInt()
            Constants.CVE_ONLY = properties.getProperty("cveOnly").toBoolean()
            Constants.REALISTIC_GEN = properties.getProperty("realisticgen").toBoolean()
            Constants.EXPERIMENTAL_GEN = properties.getProperty("experimentalgen").toBoolean()
            Constants.FIND_CWE = properties.getProperty("findcwe").toBoolean()
        }
    }
}

