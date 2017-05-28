#to do: add editquestion
#add ssl (https://cloud.google.com/compute/docs/load-balancing/http/ssl-certificates#gettingakeyandcertificate)

from google.appengine.ext import ndb
import webapp2
import jinja2
import os
import re
import hmac

# ancestor name
DEFAULT_BLOG_NAME = 'tacocat'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')

jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# code for Regular Expression validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")

# code for hashing
secret = "guest"


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        self.write(self.render_str(template, **params))

    # function to check that user's cookie contains valid user ID and hashed
    # password
    def authenticate_user(self):
        visit_cookie_str = self.request.cookies.get('user')
        if visit_cookie_str:
            visitor_id = int(visit_cookie_str.split('|')[0])
            visitor_password = visit_cookie_str.split('|')[1]
            visitor = TestUsers21.get_by_id(
                visitor_id, parent=blog_key(DEFAULT_BLOG_NAME))
            if visitor:
                if visitor_password == visitor.password:
                    return True

    def user_logged_in(self):
        visit_cookie_str = self.request.cookies.get('user')
        if not visit_cookie_str:
            return ""
        elif len(visit_cookie_str) == 0:
            print "no cookie"
            return ""
        else:
            visitor_id = int(visit_cookie_str.split('|')[0])
            visitor = TestUsers21.get_by_id(
                visitor_id, parent=blog_key(DEFAULT_BLOG_NAME))
            if visitor:
                return visitor.username
            else:
                return ""

    def admin_logged_in(self):
        visit_cookie_str = self.request.cookies.get('user')
        if not visit_cookie_str:
            return False
        elif len(visit_cookie_str) == 0:
            return False
        else:
            visitor_id = int(visit_cookie_str.split('|')[0])
            visitor = TestUsers21.get_by_id(
                visitor_id, parent=blog_key(DEFAULT_BLOG_NAME))
            if visitor:
                if visitor.username == "admin":
                    return True
            else:
                return False

    def login(self):
        login_username = self.request.get("login_username")
        login_password = self.request.get("login_password")
        print "got username and password"

        login_hashed_password = self.make_temp_password(login_password)

        user_check = ndb.gql(
            "SELECT * FROM TestUsers21 WHERE username = :user AND ANCESTOR is :ancestor",
            user=login_username,
            ancestor=blog_key(DEFAULT_BLOG_NAME))

        if user_check.get():
            print "user exists in database"
            for user in user_check:
                db_password = user.password  # hashed password from user database
                db_id = user.key.id()  # user ID from user database
            if login_hashed_password == db_password:
                # create cookie
                new_cookie = self.make_secure_val(db_id, login_password)
                # deliver cookie
                self.response.headers.add_header(
                    'Set-Cookie', 'user=%s; Path=/' %
                    new_cookie)
                print "cookie delivered"
                if self.admin_logged_in():
                    self.redirect('/addquestion')
                else:
                    self.redirect('/')
            else:
                self.render("results.html", error="Invalid password")
        else:
            self.render("results.html", error="Invalid username")

    def validate(self, input, validation):
        return validation.match(input)

    def hash_str(self, s):
        return hmac.new(secret, s).hexdigest()

    def make_secure_val(self, id, password):
        return "%s|%s" % (id, self.hash_str(password))

    def check_secure_val(self, password):
        val = h.split('|')[0]
        if h == self.make_secure_val(val):
            return val

    def make_temp_password(self, password):
        return self.make_secure_val('temp', password).split('|')[1]


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        print "logged out"
        self.redirect('/')


class Results(Handler):
    def get(self):
        adminExist = ndb.gql(
            "SELECT * FROM TestUsers21 WHERE username = :user AND ANCESTOR is :ancestor",
            user="admin",
            ancestor=blog_key(DEFAULT_BLOG_NAME))
        admin = adminExist.get()
        if not admin:
            hashed_password = self.make_temp_password('59543')
            new_user = TestUsers21(
                username='admin',
                password=hashed_password,
                parent=blog_key(DEFAULT_BLOG_NAME))
            new_user.put()
            print "new user created"
        resultList = []
        questions = ndb.gql(
            "SELECT * FROM TestQuestions21 WHERE ANCESTOR is :1",
            blog_key(DEFAULT_BLOG_NAME))
        questionList = []
        for question in questions:
            questionList = []
            votes = 0
            questionList.append(question.question)
            optionsQuery = ndb.gql(
                "SELECT * FROM TestQuestions21 WHERE question = :question AND ANCESTOR is :ancestor",
                question=question.question,
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            optionList = optionsQuery.get()
            choicesList = []
            for option in optionList.options:
                choiceList = []
                choiceList.append(option)
                users = ndb.gql(
                    "SELECT * FROM TestResults21 WHERE question = :question AND choice = :choice AND ANCESTOR is :ancestor",
                    question=question.question,
                    choice=option,
                    ancestor=blog_key(DEFAULT_BLOG_NAME))
                userList = []
                if users:
                    for user in users:
                        votes += 1
                        userList.append(user.user)
                choiceList.append(userList)
                choicesList.append(choiceList)
            questionList.append(choicesList)
            if votes == 0:
                votes = 1
            questionList.append(votes)
            resultList.append(questionList)

        self.render(
            "results.html",
            logged_in=self.authenticate_user(),
            user=self.user_logged_in(),
            admin=self.admin_logged_in(),
            results=resultList)

    def post(self):
        if self.request.get("login_username") and self.request.get(
                "login_password"):
            self.login()


class TakePoll(Handler):
    def get(self):
        user = self.user_logged_in()
        userCheck = ndb.gql(
            "SELECT * FROM TestResults21 WHERE user = :user AND ANCESTOR is :ancestor",
            user=user,
            ancestor=blog_key(DEFAULT_BLOG_NAME))
        x = 0
        for user in userCheck:
            x += 1
        if x == 0:
            if self.authenticate_user() and self.admin_logged_in() != True:
                questions = ndb.gql(
                    "SELECT * FROM TestQuestions21 WHERE ANCESTOR is :ancestor",
                    ancestor=blog_key(DEFAULT_BLOG_NAME))
                print self.admin_logged_in()
                self.render(
                    "takepoll.html",
                    logged_in=self.authenticate_user(),
                    user=self.user_logged_in(),
                    admin=self.admin_logged_in(),
                    questions=questions)
            else:
                self.redirect('/')
        else:
            self.redirect('/edit')

    def post(self):
        if self.authenticate_user() and self.admin_logged_in() != True:
            questions = ndb.gql(
                "SELECT * FROM TestQuestions21 WHERE ANCESTOR is :ancestor",
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            user = self.user_logged_in()
            for question in questions:
                question = question.question
                choice = self.request.get(question)
                current_choice = TestResults21(
                    user=user,
                    question=question,
                    choice=choice,
                    parent=blog_key(DEFAULT_BLOG_NAME))
                current_choice.put()
                print "choices saved in database"
            self.redirect('/')
        else:
            self.redirect('/')


class Edit(Handler):
    def get(self):
        choices = ndb.gql(
            "SELECT * FROM TestResults21 WHERE user = :user AND ANCESTOR is :ancestor",
            user=self.user_logged_in(),
            ancestor=blog_key(DEFAULT_BLOG_NAME))
        choiceDict = {}
        for choice in choices:
            choiceDict[choice.question] = choice.choice
        questions = ndb.gql(
            "SELECT * FROM TestQuestions21 WHERE ANCESTOR is :ancestor",
            ancestor=blog_key(DEFAULT_BLOG_NAME))
        self.render(
            "editresults.html",
            logged_in=self.authenticate_user(),
            user=self.user_logged_in(),
            admin=self.admin_logged_in(),
            choices=choiceDict,
            questions=questions)

    def post(self):
        if self.authenticate_user() and self.admin_logged_in() != True:
            oldResults = ndb.gql(
                "SELECT * FROM TestResults21 WHERE user = :user AND ANCESTOR is :ancestor",
                user=self.user_logged_in(),
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            for oldResult in oldResults:
                oldResult.key.delete()
                print "result deleted"
            questions = ndb.gql(
                "SELECT * FROM TestQuestions21 WHERE ANCESTOR is :ancestor",
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            user = self.user_logged_in()
            for question in questions:
                question = question.question
                choice = self.request.get(question)
                current_choice = TestResults21(
                    user=user,
                    question=question,
                    choice=choice,
                    parent=blog_key(DEFAULT_BLOG_NAME))
                current_choice.put()
                print "choices saved in database"
            self.redirect('/')
        else:
            self.redirect('/')


class AddQuestion(Handler):
    def get(self):
        if self.user_logged_in() == "admin":
            self.render(
                "addquestion.html",
                logged_in=self.authenticate_user(),
                user=self.user_logged_in(),
                admin=self.admin_logged_in())
        else:
            self.redirect('/logout')

    def post(self):
        if self.user_logged_in() == "admin":
            question = self.request.get("question")
            options = []
            if self.request.get("option1") != "":
                options.append(self.request.get("option1"))
            if self.request.get("option2") != "":
                options.append(self.request.get("option2"))
            if self.request.get("option3") != "":
                options.append(self.request.get("option3"))
            if self.request.get("option4") != "":
                options.append(self.request.get("option4"))
            if self.request.get("option5") != "":
                options.append(self.request.get("option5"))
            new_question = TestQuestions21(question=question, options=options,
                                           parent=blog_key(DEFAULT_BLOG_NAME))
            new_question.put()
            print "new question created"
            self.redirect('/addquestion')



# delete results associated
class DeleteQuestion(Handler):
    def get(self):
        if self.user_logged_in() == "admin":
            questions = ndb.gql(
                "SELECT * FROM TestQuestions21 WHERE ANCESTOR is :ancestor",
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            self.render(
                "deletequestion.html",
                logged_in=self.authenticate_user(),
                user=self.user_logged_in(),
                admin=self.admin_logged_in(),
                questions=questions)
        else:
            self.redirect('/logout')

    def post(self):
        if self.user_logged_in() == "admin":
            deleteQuestionQuestion = self.request.get("deletequestion")
            deleteQueryQ = ndb.gql(
                "SELECT * FROM TestQuestions21 WHERE question = :question AND ANCESTOR is :ancestor",
                question=deleteQuestionQuestion,
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            deleteQuestion = deleteQueryQ.get()
            deleteQuestion.key.delete()
            print "question deleted"
            deleteResults = ndb.gql(
                "SELECT * FROM TestResults21 WHERE question = :question AND ANCESTOR is :ancestor",
                question=deleteQuestionQuestion,
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            for deleteResult in deleteResults:
                deleteResult.key.delete()
                print "result deleted"
            self.redirect('/deletequestion')
        else:
            self.redirect('/logout')


class AddUser(Handler):
    def get(self):
        if self.user_logged_in() == "admin":
            self.render(
                "adduser.html",
                logged_in=self.authenticate_user(),
                user=self.user_logged_in(),
                admin=self.admin_logged_in())
        else:
            self.redirect('/logout')

    def post(self):
        if self.request.get("login_username") and self.request.get(
                "login_password"):
            self.login()
        else:
            username = self.request.get("username")
            password = self.request.get("password")
            verify = self.request.get("verify")

            user_error = ""
            password_error = ""
            verify_error = ""

            if self.validate(username, USER_RE) is None:
                user_error = "That's not a valid username."
            if self.validate(password, PASSWORD_RE) is None:
                password_error = "That wasn't a valid password."
            if verify != password:
                verify_error = "Your passwords didn't match."
            if user_error != "" or password_error != "" or verify_error != "":
                self.render("adduser.html", user_error=user_error,
                            password_error=password_error,
                            verify_error=verify_error,
                            username=username,
                            admin=self.admin_logged_in())
            else:
                user_check = ndb.gql(
                    "SELECT * FROM TestUsers21 WHERE username = :user AND ANCESTOR is :ancestor",
                    user=username,
                    ancestor=blog_key(DEFAULT_BLOG_NAME))
                if user_check.get():
                    user_error = "This username is already being used."
                    self.render("adduser.html", user_error=user_error,
                                password_error=password_error,
                                verify_error=verify_error,
                                username="",
                                admin=self.admin_logged_in())
                else:
                    hashed_password = self.make_temp_password(password)
                    new_user = TestUsers21(
                        username=username, password=hashed_password,
                        parent=blog_key(DEFAULT_BLOG_NAME))
                    new_user.put()
                    print "new user created"
                    self.redirect('/adduser')


class DeleteUser(Handler):
    def get(self):
        if self.user_logged_in() == "admin":
            users = ndb.gql(
                "SELECT * FROM TestUsers21 WHERE ANCESTOR is :ancestor",
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            self.render(
                "deleteuser.html",
                logged_in=self.authenticate_user(),
                user=self.user_logged_in(),
                admin=self.admin_logged_in(),
                users=users)
        else:
            self.redirect('/logout')

    def post(self):
        if self.user_logged_in() == "admin":
            deleteUsername = self.request.get("deleteuser")
            deleteQuery = ndb.gql(
                "SELECT * FROM TestUsers21 WHERE username = :user AND ANCESTOR is :ancestor",
                user=deleteUsername,
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            deleteUser = deleteQuery.get()
            deleteUser.key.delete()
            print "user deleted"
            deleteResults = ndb.gql(
                "SELECT * FROM TestResults21 WHERE user = :user AND ANCESTOR is :ancestor",
                user=deleteUsername,
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            for deleteResult in deleteResults:
                deleteResult.key.delete()
                print "result deleted"
            self.redirect('/deleteuser')
        else:
            self.redirect('/logout')

class ChangePassword(Handler):
    def get(self):
        if self.authenticate_user() and self.admin_logged_in() != True:

            self.render(
                "changepassword.html",
                logged_in=self.authenticate_user(),
                user=self.user_logged_in())
        else:
            self.redirect('/')

    def post(self):
        if self.authenticate_user() and self.admin_logged_in() != True:
            password = self.request.get("password")
            verify = self.request.get("verify")

            password_error = ""
            verify_error = ""

            userQ = ndb.gql(
                "SELECT * FROM TestUsers21 WHERE username = :user AND ANCESTOR is :ancestor",
                user=self.user_logged_in(),
                ancestor=blog_key(DEFAULT_BLOG_NAME))
            user = userQ.get()
            username = user.username

            if self.validate(password, PASSWORD_RE) is None:
                password_error = "That wasn't a valid password."
            if verify != password:
                verify_error = "Your passwords didn't match."
            if password_error != "" or verify_error != "":
                self.render("changepassword.html",
                            password_error=password_error,
                            verify_error=verify_error,
                            admin=self.admin_logged_in())
            else:
                user_check = ndb.gql(
                    "SELECT * FROM TestUsers21 WHERE username = :user AND ANCESTOR is :ancestor",
                    user=username,
                    ancestor=blog_key(DEFAULT_BLOG_NAME))

                hashed_password = self.make_temp_password(password)
                user.password = hashed_password
                user.put()
                print "password changed"

                self.redirect('/')


from tables import TestUsers21, TestResults21, TestQuestions21, blog_key
