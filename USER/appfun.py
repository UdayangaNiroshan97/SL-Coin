try: from USER.client import mysql_app, session
except ImportError as e: print(e)
import mysql.connector
from mysql.connector import Error


class Table():
    #specify table name on instance
    def __init__(self,table_name,*args):
        self.table = table_name
        self.columns = "(%s)" %",".join(args)

    #returns a dictionary of all data in the table
    def getall(self):
        cur = mysql_app.connection.cursor()
        result = cur.execute("SELECT * FROM %s" %self.table)
        data = cur.fetchall(); return data

    #gets a value from the table
    def getone(self,search,value):
        data = {}; cur = mysql_app.connection.cursor()
        result = cur.execute("SELECT * FROM %s WHERE %s = \"%s\"" %(self.table,search,value))

        if result > 0: data = cur.fetchone()
        cur.close(); return data

    #deletes a value from the table
    def deleteone(self,search,value):
        cur = mysql_app.connection.cursor()
        cur.execute("DELETE from %s where %s = \"%s\"" %(self.table,search,value))
        mysql_app.connection.commit(); cur.close()

    #deletes the table from the database
    def drop(self):
        cur = mysql_app.connection.cursor()
        cur.execute("DROP TABLE %s" %self.table)
        cur.close()

    def insert(self,*args):
        data =""
        for arg in args:
            data += "\"%s\","%(arg)

        cur = mysql_app.connection.cursor()
        cur.execute("INSERT INTO %s%s VALUES(%s)" % (self.table, self.columns,data[:len(data)-1]))
        mysql_app.connection.commit();
        cur.close()

#simplify execution of sql code
def sql_raw(execution):
    cur = mysql_app.connection.cursor()
    cur.execute(execution)
    mysql_app.connection.commit()
    cur.close()


def create_server_connection(host_name, user_name, user_password):
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            passwd=user_password
        )
        print("MySQL Database connection successful")
    except Error as err:
        print(f"Error: '{err}'")

    return connection

def create_database(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        create_tables()
    except Error as err:
        print(f"Error: '{err}'")

def create_db_connection(host_name, user_name, user_password, db_name):
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            passwd=user_password,
            database=db_name
        )
        connection.commit()
        connection.close()
    except:
        query = "CREATE DATABASE slcoin"
        connection = create_server_connection('localhost','root',"")
        create_database(connection, query)
        connection.close()

def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query successful")
    except Error as err:
        print(f"Error: '{err}'")

def create_tables():
    create_users_table = """
    CREATE TABLE users (
      username VARCHAR(20),
      password VARCHAR(250),
      public_key VARCHAR(2000)
    );
     """
    create_recover_table = """
        CREATE TABLE recover (
          public_key VARCHAR(2000),
          recover_public_key VARCHAR(2000)
        );
         """
    connection = mysql.connector.connect(
            host='localhost',
            user='root',
            passwd='',
            database='slcoin'
        )
    execute_query(connection, create_users_table)
    execute_query(connection, create_recover_table)
    connection.commit()

#check if username is not taken upon registration
def isnewuser(username):
    users = Table("users","username","password")
    data = users.getall()
    usernames = [user.get('username') for user in data]

    return False if username in usernames else True
