Directory Structure Instruction
.
├─Client
│  ├─History: search history
│  └─List: for each file f, create a list f_bar of unique keyword
├─Comm
│  └─AddToken: client will pass the add token file to server
└─Server
    ├─InvertIndex: for each keyword (search token), we store the file ID which include this keyword
    └─RegularIndex: for each file, we store its encrypted keyword

Clear.bat: Clear old file, including search history, addd token, index