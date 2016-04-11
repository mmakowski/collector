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
package lu.jimenez.research.bugsandvulnerabilities.collector.clear

import lu.jimenez.research.bugsandvulnerabilities.collector.utils.Constants
import lu.jimenez.research.bugsandvulnerabilities.collector.utils.Utils
import lu.jimenez.research.bugsandvulnerabilities.model.internal.Document
import lu.jimenez.research.bugsandvulnerabilities.utils.RegexpAndWalk
import java.io.FileNotFoundException
import java.util.*


/**
 * Class responsible of the creation of the clear set
 * No distinction is made between accurate and real as the only change is the number of iteration
 *
 * @param path path to the git repository
 *
 */
class ClearSet (val path: String) {
    val pathToRepo = path + ".git"

    /**
     * Method to retrieve the lis of all files of a repository that are not present in a given list
     *
     * @param listOfALreadyUsedFile list of Files that have been declared as buggy or vulnerable
     *
     * @return list of Files
     */
    fun setOfClearFile(listOfALreadyUsedFile: Set<String>): List<String> {
        val listFiles = RegexpAndWalk.recursiveListOfFilesOfADirectory(path) as MutableList<String>
        listFiles.removeAll(listOfALreadyUsedFile)
        Collections.shuffle(listFiles)
        return listFiles
    }


    /**
     * Method creating the clear file dataset  from the list of vulnerable commit and the list of clear file in history
     *
     * @param listOfCommittoWorkOn list of vulnerable commits
     * @param listOfClearFile list of file obtain from the setOfClearFiles methods
     * @param numberOfRequiredIteration number of clear file per vulnerability typically one for accurate and 16 for real
     *
     * linked list is used to select the first element and to add it at the end when the iteration is over
     * @return list of clear file ([Document])
     */
    fun createClearSet(listOfCommittoWorkOn: List<String>, listOfClearFile: List<String>): List<Document> {
        return Utils.createDocumentFromTimeOfVuln(listOfCommittoWorkOn, Constants.CLEAR_SHARE,listOfClearFile,pathToRepo )
    }
}