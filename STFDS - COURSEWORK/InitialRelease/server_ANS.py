#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the missing backend functionality
# You should only need to extend this file. The client side code
# (html, javascript and css) is complete and does not require editing
# or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie                              # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib                                              # some url parsing support
import sqlite3                                             # sql database
import random                                              # generate random numbers
import time                                                # needed to record when stuff happened
import json                                                # support for json encoding
import sys                                                 # needed for agument handling
import numpy as np
### Database access wrappers

def do_database_execute(op, parameters):
    """Execute an SQL command that is not expected to return any rows."""
    print(op)
    try:
        db = sqlite3.connect('database.db') # DO NOT CHANGE THE NAME OF THE DATABASE
        cursor = db.cursor()
        cursor.execute(op, parameters)
        db.commit()
    except Exception as e:
        db.rollback()
    finally:
        db.close()

def do_database_fetchone(op, parameters):
    """Execute an SQL command that returns at most a single row."""
    print(op)
    try:
        db = sqlite3.connect('database.db') # DO NOT CHANGE THE NAME OF THE DATABASE
        cursor = db.cursor()
        cursor.execute(op, parameters)
        result = cursor.fetchone()
        print(result)
        db.close()
        return result
    except Exception as e:
        print(e)
        return None

def do_database_fetchall(op, parameters):
    """Execute an SQL command that can return any number of rows, including none."""
    print(op)
    try:
        db = sqlite3.connect('database.db') # DO NOT CHANGE THE NAME OF THE DATABASE
        cursor = db.cursor()
        cursor.execute(op, parameters)
        result = cursor.fetchall()
        print(result)
        db.close()
        return result
    except Exception as e:
        print(e)
        return None


### The following build_ functions return the responses that the front end client understands.
### You can user these to build a list of responses

def build_response_message(code, text):
    """This function builds a message response that displays a message
       to the user on the web page. It also returns an error code."""
    return {"type":"message","code":code, "text":text}

def build_response_vcount(vtype,total):
    """This function builds a summary response for a vehicle type"""
    return {"type":"vcount", "vtype":vtype, "count":total}

def build_response_location(id, name):
    """This function builds an activity response that 
        contains the id and name of an activity type,"""
    return {"type":"location", "id":id, "name":name}

def build_response_total(total):
    """The number of vehicles that have been seen in this session."""
    return {"type":"total", "total":total}

def build_response_redirect(where):
    """This function builds the page redirection response
       It indicates which page the client should fetch.
       If this action is used, it should be the only response provided."""
    return {"type":"redirect", "where":where}

### Some utility code

def random_digits(n):
    """Return a random string of digits of size n"""
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return random.randint(range_start, range_end)

def timestamp():
    """Return number of seconds since the start of the epoch"""
    return int(time.time())

def location_response(sessionid):
    """Work out how many vehicles we've seen in this session, regardless of location."""
    tot_query = "SELECT sum(mode) FROM traffic WHERE sessionid =? GROUP BY sessionid"
    total = do_database_fetchone(tot_query, (sessionid,))
    if total:
        return build_response_total(total[0])
    else:
        return build_response_total(0)

def handle_validate(iuser, imagic):
    """Check if the supplied userid and magic match a currently active 
    session and return the sessionid if they do, otherwise 0"""
    result = do_database_fetchone('SELECT * FROM session WHERE session.end=0 AND session.userid=? AND session.magic=?', (iuser, imagic,))
    if result is not None:
        return result[0]
    else:
        return 0 #not a valid sessionid

### The main command handler functions. The are the functions invoked when the json requests
### includes a specific command.
def handle_login_request(iuser, imagic, content):
    """Deal with a login request"""
    response = []

    if 'username' in content and 'password' in content:
        username = content['username']
        password = content['password']

        # Check if the username and password match in the database
        user_query = "SELECT * FROM users WHERE username =? AND password =?"
        user_result = do_database_fetchone(user_query, (username, password,))

        if user_result:
            # Generate a random magic identifier for the session
            magic = str(random_digits(8)) #we should really test its not present.
            start = timestamp()

            # close any existing sessions but updating any zero end times to the current time
            end_query = "UPDATE session SET end =? WHERE userid =? AND end=0"
            do_database_execute(end_query, (start, user_result[0], ))

            # Create a new session record in the session table
            session_query = """INSERT INTO session (sessionid, userid,
                                    magic,start,end) VALUES (NULL,?,?,?,0)"""
            do_database_execute(session_query, (user_result[0], magic, start,))

            # Return user details and the generated magic identifier
            response.append(build_response_redirect('/index.html'))

            iuser = user_result[0] if user_result else ''
            imagic = magic if user_result else ''
        else:
            response.append(build_response_message(103, 'Invalid credentials. One or both of Username and Password are incorrect or empty.'))
            return ['','', response]

    else:
        response.append(build_response_message(200, 'Missing username or password field in request.'))
        return ['','', response]


    return [iuser, imagic, response]



def handle_logout_request(iuser, imagic, parameters):
    """Deal with a logout request"""
    response = []

    if imagic and iuser :
        end = timestamp()
        # End the user's session by removing the session record
        end_query = "UPDATE session SET end=? WHERE userid =? AND magic=? AND end = 0'"
        do_database_execute(end_query, (end, iuser, imagic,))

        # Return a message indicating successful logout
        response.append(build_response_redirect('/logout.html'))  # Redirect to the index page after logout
    else:
        response.append(build_response_message(110, 'User is not logged in'))


    return ['', '', response]

def handle_location_request(iuser, imagic, content):
    """Return a list of current locations."""
    response = []
    sessionid = handle_validate(iuser, imagic)
    if sessionid == 0:
        response.append(build_response_redirect('/login.html'))
        return ['', '', response]
    else:
        loc_query = "SELECT * FROM locations ORDER BY locationid"
        locs = do_database_fetchall(loc_query, ())

        for l in locs:
            response.append(build_response_location(l[0],l[1]))

        response.append(location_response(sessionid))

        return [iuser, imagic, response]


## The user has requested a vehicle be added to the count
## content['location'] the location to be recorded
## content['occupancy'] the occupant count to be recorded
## content['type'] the type to be recorded
## Return the username, magic identifier (these may be empty strings) and the response action set.
def handle_add_request(iuser, imagic, content):
    """Adds a vehicle to the traffic record."""
    response  = []
    sessionid = handle_validate(iuser, imagic)
    if sessionid == 0:
        response.append(build_response_redirect('/login.html'))
        return ['', '', response]

    ## a valid session so process the addition of the entry.

    # First check that all the arguments are present
    else:
        try:
            if content['location'] == None:
                raise Exception('Missing location field')
            else:
                location = content['location']
        except:
            response.append(build_response_message(201,"Location field missing from request."))
            return [iuser,imagic, response]

        try:
            if content['type'] == None:
                raise Exception('Missing vehicle type')
            else:
                vtype = content['type']
        except:
            response.append(build_response_message(202,"Type field missing from request."))
            return [iuser,imagic, response]

        try:
            if content['occupancy'] == None:
                raise Exception('Missing occupancy')
            else:
                occupancy = content['occupancy']
        except:
            response.append(build_response_message(203,"Occupancy field missing from request."))
            return [iuser,imagic, response]

    # Then check that they are valid values
        try:
            if type(location) == float:
                raise Exception('Invalid location - must be integer')
            else:
                location = int(location)
                loc_query = "SELECT * FROM locations WHERE locationid =?"
                loc_result = do_database_fetchone(loc_query, (location, ))
                location = loc_result[0] # should fail if we could n't find it.
        except:
            response.append(build_response_message(101,"Location field invalid."))
            return [iuser,imagic, response]

        try:
            if type(vtype) == float:
                raise Exception('Invalid vehicle type - must be integer')
            else:
                vtype = int(vtype)
                if vtype<1 or vtype>8:
                    raise Exception("Out of range")
        except:
            response.append(build_response_message(102,"Type field invalid."))
            return [iuser,imagic, response]

        try:
            if type(occupancy) == float:
                raise Exception('Invalid occupancy')
            else:
                occupancy = int(occupancy)
                if occupancy<1 or occupancy>4:
                    raise Exception("Out of range")
        except:
            response.append(build_response_message(103,"Occupancy field invalid."))
            return [iuser,imagic, response]

    # Everything looks good, so add the record

    now = timestamp()
    add_query = """INSERT INTO traffic (recordid,
                        sessionid, time, type, locationid,
                        occupancy, mode) VALUES (NULL,?,?,?,?,?,1)"""
    do_database_execute(add_query, (sessionid, now, vtype, location, occupancy,))
    response.append(build_response_message(0,"Vehicle added for "+loc_result[1]))
    print(now)
    # Work out how many vehicles we've seen in this session, regardless of location.
    response.append(location_response(sessionid))
    return [iuser,imagic,response]

## The user has requested a vehicle be undone from the count
## content['location'] the location to be undone
## content['occupancy'] the occupant count to be undone
## content['type'] the type to be undone
## Return the username, magic identifier (these may be empty  strings) and the response action set.
def handle_undo_request(iuser, imagic, content):
    response  = []
    sessionid = handle_validate(iuser, imagic)
    if sessionid == 0:
        response.append(build_response_redirect('/login.html'))
        return ['', '', response]
    else:

    ## CODE NEEDED HERE
    ##
    ## Add code here to undo a matching vehicle if one exists.
    ## Otherwise, report an error that there is no match.
    ## Undoing does not delete an entry. It adds an equal but opposite entry

    ## check for a valid session, if so process the addition of the entry.

    # First check that all the arguments are present
        try:
            if content['location'] == None:
                raise Exception('Missing location field')
            else:
                location = content['location']
        except:
            response.append(build_response_message(201, 'Location field missing from query.'))
            return[iuser, imagic, response]

        try:
            if content['type'] == None:
                raise Exception('Missing vehicle type')
            else:
                vtype = content['type']
        except:
            response.append(build_response_message(202, 'Type of vehicle missing from query.'))
            return[iuser, imagic, response]

        try:
            if content['occupancy'] == None:
                raise Exception('Missing occupancy')
            else:
                occupancy = content['occupancy']
        except:
            response.append(build_response_message(203, 'Number of people in vehicle missing from query'))
            return[iuser, imagic, response]
    #  Then check that they are valid value
        try:
            if type(location) == float:
                raise Exception('Invalid location - must be integer')
            else:
                location = int(location)
                loc_query = f"SELECT * FROM locations WHERE locationid =?"
                loc_result = do_database_fetchone(loc_query, (location,))
                location = loc_result[0]
        except:
            response.append(build_response_message(101, 'Location of vehicle does not exist. '))
            return[iuser, imagic, response]

        try:
            if type(vtype) == float:
                raise Exception('Invalid vehicle type - must be integer')
            else:
                vtype = int(vtype)
                if vtype < 1 or vtype > 8:
                    raise Exception('Out of range. ')
        except:
            response.append(build_response_message(102, 'Type of vehicle does not exist. '))
            return[iuser, imagic, response]

        try:
            if type(occupancy) == float:
                raise Exception('Invalid occupancy')
            else:
                n_people = int(occupancy)
                if n_people < 1 or n_people > 4:
                    raise Exception('Out of range. ')
        except:
            response.append(build_response_message(103, 'Number of people in vehicle does not exist. '))
            return[iuser, imagic, response]

        try:
            n_added_query = '''SELECT COUNT(mode) FROM traffic WHERE mode=1 and
                                    sessionid =? and type =? and occupancy =? and locationid =?'''

            n_removed_query = '''SELECT COUNT(mode) FROM traffic WHERE mode= -1 and
                                    sessionid =? and type =? and occupancy =? and locationid =?'''
            if do_database_fetchone(n_added_query, (sessionid,vtype,n_people,location, )) <= do_database_fetchone(n_removed_query, (sessionid,vtype,n_people,location, )):
                raise Exception(' More undo than add')
        except:
            response.append(build_response_message(104, 'Entry does not exist. '))
            return[iuser, imagic, response]


    add_time_query = '''SELECT time, count(*) FROM traffic WHERE
                            mode=1 and sessionid=? and type=? and
                            occupancy=? and locationid=? Group by
                            time order by time desc'''

    undo_time_query = '''SELECT time, count(*) FROM traffic WHERE
                            mode=-1 and sessionid=? and type=? and
                            occupancy=? and locationid=? GROUP BY
                            time order by time desc'''
    add_t_count = do_database_fetchall(add_time_query, (sessionid, vtype, n_people, location,))
    undo_t_count = do_database_fetchall(undo_time_query, (sessionid, vtype, n_people, location,))

    add_t_dict = {atc[0]:atc[1] for atc in add_t_count}
    undo_t_dict = {utc[0]:utc[1] for utc in undo_t_count}

    next_undo = None
    for t in add_t_dict:
        if t in undo_t_dict and undo_t_dict[t] >= add_t_dict[t]:
            continue
        else:
            next_undo = t
            break


    # Update database
    if next_undo != None:
        remove_query = """INSERT INTO traffic (recordid, sessionid, time, type,
                                locationid, occupancy, mode) VALUES (NULL,?,?,?,?,?,-1)"""
        do_database_execute(remove_query, (sessionid, next_undo, vtype, location, occupancy, ))
    else:
        raise Exception('No entry exists')

    response.append(build_response_message(0,"Vehicle removed for "+loc_result[-1]))

    # Work out how many vehicles we've seen in this session, regardless of location.
    response.append(location_response(sessionid))

    return [iuser,imagic,response]
    # create response

def handle_download_request(iuser, imagic, content):
    """Provide a CSV file of all traffic observations. 
    The data is summarised into one row per date and location pair"""
    sessionid = handle_validate(iuser, imagic)
    if sessionid == 0:
        return ['', '', ""]
    else:
	# The CSV header line.
        response = "Date, Location ID, Location Name, Car, Bus, Bicycle, Motorbike, Van, Truck, Taxi, Other\n"
        #Finding all adds - query
        add_time_query = 'SELECT time FROM traffic WHERE mode = 1 ORDER by time ASC'
        #Finding all undos - query
        undo_time_query = 'SELECT time FROM traffic WHERE mode= -1 ORDER by time ASC'

        #Applying above queries
        all_add_timestamps = do_database_fetchall(add_time_query, ())
        all_undo_timestamps = do_database_fetchall(undo_time_query, ())

        #Getting the above into a list
        listed_add_t = [aat for times_add in all_add_timestamps for aat in times_add]
        listed_undo_t = [aut for times_undo in all_undo_timestamps for aut in times_undo]

        #Generating a copy of adds to not affect the loop when checking if undo is in add
        valid_adds_full = listed_add_t.copy()

        #Loop checking to see if any undos are present in adds
        # based on timestamp - if so, removes the timestamp from the copy

        valid_adds = np.unique(valid_adds_full).tolist()
        #Dictionary containing the location id and their respective names
        location_dictionary = {1 : 'Main Road (North)', 2 : 'Main Road (South)', 3 : 'Other Road (East)', 4 : 'Other Road (West)'}

        #Respective locations for each timestamp
        valid_adds_location = []
        for t in valid_adds:
            location_query = 'SELECT locationid FROM traffic WHERE time =?'
            result_loc = do_database_fetchone(location_query, (t, ))[0]
            valid_adds_location.append(result_loc)

        valid_adds_id_name = []
        for val in valid_adds_location:
            valid_adds_id_name.append(val)
            valid_adds_id_name.append(location_dictionary[val])


        #Empty list which will contain the converted timestamps
        valid_adds_date = []

        #loop that converts the timestamp into the dates
        for v_t in valid_adds:
            valid_t_q = "SELECT date(time, 'unixepoch') from traffic where time =?"
            dates = do_database_fetchall(valid_t_q, (v_t, ))[0][0]
            valid_adds_date.append(dates)


        #Empty list that will contain all the values of the vehicle counts
        #Loop that goes through the

        v_count_none = []
        n_dates = 0
        dated = []
        for va in valid_adds:
            dated.append(time.strftime('%Y-%M-%D', time.gmtime(va)))

        for va in valid_adds:
            for l in range(1,5):
                v_count_none.append(valid_adds_date[n_dates])
                v_count_none.append(l)
                v_count_none.append(location_dictionary[l])
                for v in range(1,9):

                    sum_result = do_database_fetchone('SELECT SUM(mode) from traffic where time =? and locationid =? and type =?', (va, l, v,))
                    if sum_result[0] == []:
                        v_count_none.append(0)
                    else:
                        v_count_none.append(sum_result[0])

                sum_adds = do_database_fetchone('SELECT COUNT(mode) from traffic where mode =1 and time = ? and locationid=?',(va, l,))
                v_count_none.append(sum_adds[0])
            n_dates += 1
        v_count = [0 if i == None else i for i in v_count_none]

        loc_index = 0
        v_count_separate_location = []

        while loc_index <= len(v_count):
            v_count_separate_location.append(v_count[loc_index : (loc_index + 12)])
            loc_index += 12

        unique_dates = []
        for d in valid_adds_date:
            if d in unique_dates:
                continue
            else:
                unique_dates.append(d)

        summed_v_count = []
        array_v_count = np.array(v_count_separate_location[:-1], dtype = object)

        for d in unique_dates:
            for l in location_dictionary:
                filter = (array_v_count[:, 0] == d) & (array_v_count[:, 1] == l) & (array_v_count[:, 2] == location_dictionary[l])
                filtered_count = array_v_count[:][filter]
                summed_filter_count = np.sum(filtered_count[:, 3:].astype(int), axis=0)
                summed_v_count.append([d, l, location_dictionary[l], summed_filter_count.tolist()])

        final_response = [svc[:-1] + svc[-1] for svc in summed_v_count]

        for fr in final_response:
            #if all(fr[3:] == 0):
            if fr[3] == 0 and fr[4] == 0 and fr[5] == 0 and fr[6] == 0 and fr[7] == 0 and fr[8] == 0 and fr[9] == 0 and fr[10] == 0 and fr[11] == 0:
                continue
            else:
                response += f'{fr[0]},{fr[1]},{fr[2]},{fr[3]},{fr[4]},{fr[5]},{fr[6]},{fr[7]},{fr[8]},{fr[9]},{fr[10]}\n'
	## CODE NEEDED HERE
        ##
        ## Provide one line for each (day, location) pair of all
        #  the vehicles of each type observed by any user.
        ## It should be sorted first by day, earliest first. And then by Location ID, lowest first.
        ##

        return [iuser, imagic, response]


def handle_summary_request(iuser,imagic,content):
    """This code handles a request for update to the session summary values."""
    response = []
    sessionid = handle_validate(iuser, imagic)
    if sessionid == 0:
        response.append(build_response_redirect('/login.html'))
        return ['','',response]
    else:

        try:
            location = content['location']
        except:
            response.append(build_response_message(201,"Location field missing from request."))
            return [iuser,imagic, response]

        try:
            location = int(location)
            loc_query = f"SELECT * FROM locations WHERE locationid =?"
            loc_result = do_database_fetchone(loc_query, (location, ))
            location = loc_result[0] # should fail if we could n't find it.
        except:
            response.append(build_response_message(101,"Location field invalid."))
            return [iuser,imagic, response]

    for loop in range(1,9):

        result = do_database_fetchone("SELECT SUM(mode) FROM traffic WHERE sessionid=? AND type=? AND locationid =?", (sessionid, loop, location, ))
        if result[0] != None:
            response.append(build_response_vcount(loop, result[0]))
        else:
            response.append(build_response_vcount(loop, 0))

    response.append(build_response_message(0, f"Summary compiled for {loc_result[1]}."))

    return [iuser,imagic,response]


# HTTPRequestHandler class is extended to include new post and get request handlers
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # POST This function responds to GET requests to the web server.
    def do_POST(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        if parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request

            # extract the content from the POST request.
            # This are passed to the handlers.
            length =  int(self.headers.get('Content-Length'))
            scontent = self.rfile.read(length).decode('ascii')
            print(scontent)
            if length > 0 :
                content = json.loads(scontent)
            else:
                content = []

            # deal with get parameters
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in content:
                # check if one of the parameters supplied was 'command'
                # If it is, identify which command and call the appropriate handler function.
                # You should not need to change this code.
                if content['command'] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], content)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif content['command'] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif content['command'] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif content['command'] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif content['command'] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif content['command'] == 'location':
                    [user, magic, response] = handle_location_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that
                    # to the user. This uses a special error code that is
                    # not part of the codes you will use.
                    response = []
                    response.append(build_response_message(901, 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                # This uses a special error code that is not part of the codes you will use.
                response = []
                response.append(build_response_message(902,'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404) # a file not found html response
            self.end_headers()
        return

   # GET This function responds to GET requests to the web server.
   # You should not need to change this function.
   # It deals with all files except /download.csv for which it invokes
   # handle_download_request() which your are responsible for completing.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())

        # Return a Javascript file.
        # These contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./pages/index.html', 'rb') as file:
                self.wfile.write(file.read())

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            try:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                with open('./pages'+parsed_path.path, 'rb') as file:
                    self.wfile.write(file.read())
            except:
                # The names file has not been found
                self.send_response(404)
                self.end_headers()

        # We also provide a special downloaded csv file.
        elif parsed_path.path == '/download.csv':
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.end_headers()
            [user, magic, response] = handle_download_request(user_magic[0], user_magic[1], '')
            self.wfile.write(bytes(response, 'utf-8'))
        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()

        return



def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # When testing you should supply a command line argument in the 8081+ range

    # Changing code below this line may break the test
    # environment. There is no good reason to do so.
    if len(sys.argv)<2: # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return until the server is aborted.

run()
