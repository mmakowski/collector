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
package lu.jimenez.research.bugsandvulnerabilities.collector.utils

import lu.jimenez.research.bugsandvulnerabilities.model.internal.Document
import lu.jimenez.research.bugsandvulnerabilities.utils.git.GitUtilitary
import java.io.FileNotFoundException
import java.util.*



object Utils {
    /**
     * Method creating a dataset of files from a given list and from the time of given commit
     *
     * @param listOfCommittoWorkOn typically list of vulnerable commits
     * @param listOfFilesToConsider can be clear or buggy
     * @param numberOfRequiredIteration number of files per commit
     *
     * linked list is used to select the first element and to add it at the end when the iteration is over
     * @return list of clear file ([Document])
     */
    fun createDocumentFromTimeOfVuln(listOfCommittoWorkOn: List<String>, numberOfRequiredIteration: Int, listOfFilesToConsider: List<String>, pathToRepo: String): List<Document> {
        val listOfClear = ArrayList<Document>()
        val gitUtilitary = GitUtilitary(pathToRepo)
        val linkedListOfClearFile = LinkedList<String>(listOfFilesToConsider)
        for (commit in listOfCommittoWorkOn) {
            val time = gitUtilitary.getTimeCommit(commit)
            var i = 0
            while (i < numberOfRequiredIteration) {
                val name = linkedListOfClearFile.poll()
                try {
                    val content = gitUtilitary.retrievingFileFromSpecificCommit(commit, name)
                    listOfClear.add(Document(name, time, commit, content))
                    i++
                } catch(e: FileNotFoundException) {
                    println("$name is not working with $commit ")
                } finally {
                    linkedListOfClearFile.add(name)
                }
            }
        }
        return listOfClear
    }
}