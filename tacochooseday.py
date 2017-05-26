import webapp2
import os
import jinja2
import re
import hmac
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# code for Regular Expression validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")


def validate(input, validation):
    return validation.match(input)


# code for hashing
secret = "guest"


def hash_str(s):
    return hmac.new(secret, s).hexdigest()


def make_secure_val(id, password):
    return "%s|%s" % (id, hash_str(password))


def check_secure_val(password):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_temp_password(password):
    return make_secure_val('temp', password).split('|')[1]


# code to create user table
class TestUsers21(db.Model):
    username = db.StringProperty(required=True)  # username
    password = db.StringProperty(required=True)  # hashed password
    # datetime stamp of creation of user
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# code to create question table
class TestQuestions21(db.Model):
    question = db.StringProperty(required=True)
    options = db.StringListProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class TestResults21(db.Model):
    choice = db.StringProperty()
    question = db.StringProperty()
    user = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


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
            visitor = TestUsers21.get_by_id(visitor_id)
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
            visitor = TestUsers21.get_by_id(visitor_id)
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
            visitor = TestUsers21.get_by_id(visitor_id)
            if visitor:
                if visitor.username == "admin":
                    return True
            else:
                return False

    def login(self):
        login_username = self.request.get("login_username")
        login_password = self.request.get("login_password")
        print "got username and password"

        login_hashed_password = make_temp_password(login_password)

        user_check = db.GqlQuery(
            "SELECT * FROM TestUsers21 WHERE username = :user",
            user=login_username)

        if user_check.get():
            print "user exists in database"
            for user in user_check:
                db_password = user.password  # hashed password from user database
                db_id = user.key().id()  # user ID from user database
            if login_hashed_password == db_password:
                # create cookie
                new_cookie = make_secure_val(db_id, login_password)
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


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        print "logged out"
        self.redirect('/')


class Results(Handler):
    def get(self):
        #josh add Admin user if does not exist
        adminExist = db.GqlQuery("SELECT * FROM TestUsers21 WHERE user = :user", user = "admin")
        admin = adminExist.get()
        if not admin:
            hashed_password = make_temp_password('59543')
            new_user = TestUsers21(
                username='admin', password=hashed_password)
            new_user.put()
            print "new user created"
            time.sleep(.1)
        resultList = []
        questions = db.GqlQuery("SELECT * FROM TestQuestions21")
        questionList = []
        for question in questions:
            questionList = []
            votes = 0
            questionList.append(question.question)
            optionsQuery = db.GqlQuery("SELECT * FROM TestQuestions21 WHERE question = :question", question = question.question)
            optionList = optionsQuery.get()
            choicesList = []
            for option in optionList.options:
                choiceList = []
                choiceList.append(option)
                users = db.GqlQuery("SELECT * FROM TestResults21 WHERE question = :question AND choice = :choice", question = question.question, choice = option)
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
        userCheck = db.GqlQuery("SELECT * FROM TestResults21 WHERE user = :user", user=user)
        x = 0
        for user in userCheck:
            x += 1
        if x == 0:
            if self.authenticate_user() and self.admin_logged_in() != True:
                questions = db.GqlQuery("SELECT * FROM TestQuestions21")
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
            questions = db.GqlQuery("SELECT * FROM TestQuestions21")
            user = self.user_logged_in()
            for question in questions:
                question = question.question
                choice = self.request.get(question)
                current_choice = TestResults21(user=user, question=question, choice=choice)
                current_choice.put()
                print "choices saved in database"
                time.sleep(.1)
            self.redirect('/')
        else:
            self.redirect('/')

class Edit(Handler):
    def get(self):
        choices = db.GqlQuery("SELECT * FROM TestResults21 WHERE user = :user", user = self.user_logged_in())
        choiceDict = {}
        for choice in choices:
            choiceDict[choice.question] = choice.choice
        questions = db.GqlQuery("SELECT * FROM TestQuestions21")
        self.render(
            "editresults.html",
            logged_in=self.authenticate_user(),
            user=self.user_logged_in(),
            admin=self.admin_logged_in(),
            choices=choiceDict,
            questions=questions)

    def post(self):
        if self.authenticate_user() and self.admin_logged_in() != True:
            oldResults = db.GqlQuery("SELECT * FROM TestResults21 WHERE user = :user", user = self.user_logged_in())
            for oldResult in oldResults:
                TestResults21.delete(oldResult)
                print "result deleted"
            questions = db.GqlQuery("SELECT * FROM TestQuestions21")
            user = self.user_logged_in()
            for question in questions:
                question = question.question
                choice = self.request.get(question)
                current_choice = TestResults21(user=user, question=question, choice=choice)
                current_choice.put()
                print "choices saved in database"
                time.sleep(.1)
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
            new_question = TestQuestions21(question=question, options=options)
            new_question.put()
            print "new question created"
            time.sleep(.1)
            self.redirect('/')


#delete results associated
class DeleteQuestion(Handler):
    def get(self):
        if self.user_logged_in() == "admin":
            questions = db.GqlQuery("SELECT * FROM TestQuestions21")
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
            deleteQueryQ = db.GqlQuery("SELECT * FROM TestQuestions21 WHERE question = :question", question=deleteQuestionQuestion)
            deleteQuestion = deleteQueryQ.get()
            TestQuestions21.delete(deleteQuestion)
            print "question deleted"
            deleteResults = db.GqlQuery("SELECT * FROM TestResults21 WHERE question = :question", question=deleteQuestionQuestion)
            for deleteResult in deleteResults:
                TestResults21.delete(deleteResult)
                print "result deleted"
            time.sleep(.1)
            self.redirect('/')
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

            if validate(username, USER_RE) is None:
                user_error = "That's not a valid username."
            if validate(password, PASSWORD_RE) is None:
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
                user_check = db.GqlQuery(
                    "SELECT * FROM TestUsers21 WHERE username = :user",
                    user=username)
                if user_check.get():
                    user_error = "This username is already being used."
                    self.render("adduser.html", user_error=user_error,
                                password_error=password_error,
                                verify_error=verify_error,
                                username="",
                                admin=self.admin_logged_in())
                else:
                    hashed_password = make_temp_password(password)
                    new_user = TestUsers21(
                        username=username, password=hashed_password)
                    new_user.put()
                    print "new user created"
                    time.sleep(.1)
                    self.redirect('/')


class DeleteUser(Handler):
    def get(self):
        if self.user_logged_in() == "admin":
            users = db.GqlQuery("SELECT * FROM TestUsers21")
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
            deleteQuery = db.GqlQuery("SELECT * FROM TestUsers21 WHERE username = :user", user=deleteUsername)
            deleteUser = deleteQuery.get()
            TestUsers21.delete(deleteUser)
            print "user deleted"
            deleteResults = db.GqlQuery("SELECT * FROM TestResults21 WHERE user = :user", user=deleteUsername)
            for deleteResult in deleteResults:
                TestResults21.delete(deleteResult)
                print "result deleted"
            time.sleep(.1)
            self.redirect('/')
        else:
            self.redirect('/logout')


app = webapp2.WSGIApplication([('/logout', Logout),
                               ('/', Results),
                               ('/takepoll', TakePoll),
                               ('/edit', Edit),
                               ('/addquestion', AddQuestion),
                               ('/deletequestion', DeleteQuestion),
                               ('/adduser', AddUser),
                               ('/deleteuser', DeleteUser)
                               ],
                              debug=True)
