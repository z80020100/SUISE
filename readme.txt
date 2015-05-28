Client:
	List: for each file f, create a list f_bar of unique keyword
	History: search history

Server:
	RegularIndex: for each file, we store its encrypted keyword
	InvertIndex: for each keyword (search token), we store the file ID which include this keyword
	
Comm: communication between client and server