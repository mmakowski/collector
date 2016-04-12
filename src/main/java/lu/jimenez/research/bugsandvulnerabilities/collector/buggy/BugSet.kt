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
package lu.jimenez.research.bugsandvulnerabilities.collector.buggy

import lu.jimenez.research.bugsandvulnerabilities.collector.utils.Constants
import lu.jimenez.research.bugsandvulnerabilities.collector.utils.Utils
import lu.jimenez.research.bugsandvulnerabilities.model.BuggyFile
import lu.jimenez.research.bugsandvulnerabilities.model.internal.Document
import lu.jimenez.research.bugsandvulnerabilities.utils.MultiThreading
import lu.jimenez.research.bugsandvulnerabilities.utils.RegexpAndWalk
import lu.jimenez.research.bugsandvulnerabilities.utils.git.GitUtilitary
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.api.errors.GitAPIException
import org.eclipse.jgit.revwalk.RevCommit
import java.io.File
import java.io.IOException
import java.util.*


class BugSet(path: String) {
    val pathToRepo = "$path.git"

    /**
     * Method to create a list of all commit containing one of the keyword
     *
     * @param listOfAlreadyUsedCommit list of vulnerability commits to avoid double
     * @param bugTracker should we use reference to bug tracker (true) (better reliability) or default keywords
     *
     * @return list of commit
     */
    fun populatewithBug(listOfAlreadyUsedCommit: List<String>? = null, bugTracker: Boolean): List<Pair<String,String>?>? {
        try {
            val git = Git.open(File(pathToRepo))
            val commits = git.log().all().call().toList()
            val listOfKeywords: List<String>
            if (bugTracker) {
                listOfKeywords = listOf(Constants.BUG_TRACKER)
            } else {
                listOfKeywords = Constants.DEFAULT_BUG_INDICATORS
            }
            return MultiThreading.onFunctionWithSingleOutput(commits, { commit -> processingCommitBug(commit, listOfAlreadyUsedCommit, listOfKeywords, bugTracker) }, Constants.NB_THREAD)
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: GitAPIException) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * Method to generate a Buggy dataset (Multithread)
     *
     * @param listOfBug list of bug commit
     *
     * @return list of [BuggyFile]
     */
    fun createBuggyDataset(listOfBug: List<Pair<String, String>?>): List<BuggyFile> {
        try {
            val gitUtilitary = GitUtilitary(pathToRepo)
            val buggySet = MultiThreading.onFunctionWithListOutput(listOfBug, { entry -> generatingBuggyFiles(entry, gitUtilitary) }, Constants.NB_THREAD)
            gitUtilitary.close()
            return buggySet
        } catch(e: IOException) {
            e.printStackTrace()
        }
        return listOf()
    }

    /**
     * Method to retrieve all files that were concern by a commit mentionning a bug
     *
     * @param listOfBug list of commit mentionning bug
     *
     * @return set of files
     */
    fun setOfBugFiles(listOfBug: List<Pair<String,String>?>?, listOfVulnerableFiles: Set<String>): Set<String> {
        val setOfBuggyFiles = HashSet<String>()
        val gitUtilitary = GitUtilitary(pathToRepo)
        setOfBuggyFiles.addAll(MultiThreading.onFunctionWithListOutput(listOfBug!!, { entry -> generatingListOfFile(entry?.first, listOfVulnerableFiles, gitUtilitary) }, Constants.NB_THREAD))
        gitUtilitary.close()
        return setOfBuggyFiles
    }

    /**
     * Method to generate the buggy set
     * Take [Constants].BUG_SHARE buggy file at the time of the vulnerability
     *
     * @param listOfBugFilesInHistory
     * @param listOfCommitVulnerable list of vulnerability
     */
    fun createFilesHistoricallyBuggyDataset(listOfCommitVulnerable: Map<String, Int>, listOfBugFilesInHistory: Set<String>): List<Document> {
        return Utils.createDocumentFromTimeOfVuln(listOfCommitVulnerable, Constants.BUG_SHARE, listOfBugFilesInHistory.toList(), pathToRepo)
    }

    /**
     * Method to generate a list of buggy file from a buggy commit
     *
     * @param entryhash of the commit and link to bugzilla
     * @param gitUtilitary git utilitary from the utils module
     *
     * @return list of Buggy File
     */
    fun generatingBuggyFiles(entry: Pair<String, String>?, gitUtilitary: GitUtilitary): List<BuggyFile> {
        val listOfBuggy = ArrayList<BuggyFile>()
        val commit = entry!!.first
        val bugTracker = entry.second
        val fullMessage = gitUtilitary.getCommitMessage(commit)
        val time = gitUtilitary.getTimeCommit(commit)
        val listOfModifiedFile = gitUtilitary.getListOfModifiedFile(commit, Constants.FILE_EXTENSION)
        for (file in listOfModifiedFile) {
            val newName = file
            val previousCommit = gitUtilitary.previousCommitImpactingAFile(file, commit)
            val oldname = previousCommit!!.filePath
            val oldHash = previousCommit.revCommit.name
            val oldTime = gitUtilitary.getTimeCommit(oldHash)
            val oldContent = gitUtilitary.retrievingFileFromSpecificCommit(oldHash, oldname)
            val newContent = gitUtilitary.retrievingFileFromSpecificCommit(commit, newName)

            val buggyDoc = Document(oldname, oldTime, oldHash, oldContent)
            val patchedDoc = Document(newName, time, commit, newContent)
            listOfBuggy.add(BuggyFile(buggyDoc, patchedDoc, fullMessage, bugTracker))
        }
        return listOfBuggy
    }

    companion object BuggySideFunction {
        /**
         * Method to confirm if a commit mention bug
         *
         * @param commitUnderStudy: commit under Study
         * *
         * @return hash of the commit
         */
        fun processingCommitBug(commitUnderStudy: RevCommit, listOfAlreadyUsedCommit: List<String>?, listOfKeywords: List<String>, bugTracker: Boolean): Pair<String,String>? {
            if (listOfAlreadyUsedCommit != null) {
                if (listOfAlreadyUsedCommit.contains(commitUnderStudy.name)) return null
            }
            val message = commitUnderStudy.fullMessage
            if (bugTracker) {
                val listofUrl = RegexpAndWalk.extractUrls(message)
                for (url in listofUrl) {
                    if (RegexpAndWalk.containsAKeyword(url, listOfKeywords) && !message.contains("Merge"))
                        return Pair(commitUnderStudy.name,url.replace(")", ""))
                }
            } else {
                if (RegexpAndWalk.containsAKeyword(message, listOfKeywords) && !message.contains("Merge"))
                    return Pair(commitUnderStudy.name,"")
            }
            return null
        }

        /**
         * Method to retrieve the list of file
         */
        fun generatingListOfFile(entry: String?, listOfVulnerableFiles: Set<String>, gitUtilitary: GitUtilitary): List<String> {
            val listOfbuggyFile = ArrayList<String>()
            val listOfModifiedFile = gitUtilitary.getListOfModifiedFile(entry!!, Constants.FILE_EXTENSION)
            for (file in listOfModifiedFile) {
                val newName = file
                val previousCommit = gitUtilitary.previousCommitImpactingAFile(file, entry)
                if (previousCommit != null) {
                    val oldname = previousCommit.filePath
                    if (!listOfVulnerableFiles.contains(newName) && !listOfVulnerableFiles.contains(oldname)) {
                        listOfbuggyFile.add(oldname)
                        listOfbuggyFile.add(newName)
                    }
                }
            }
            return listOfbuggyFile
        }
    }

}