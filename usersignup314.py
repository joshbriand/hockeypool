import webapp2
import os
import jinja2
import re
import hmac
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

#code for Regular Expression validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

#code for Regular Expression validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def validate(input, validation):
	return validation.match(input)

#code for hashing
secret = "password"

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


#code to create user database
class TestPoolUserDB(db.Model):
	username = db.StringProperty(required = True) #username
	password = db.StringProperty(required = True) #hashed password
	email = db.StringProperty(required = True) #email address or "none"
	created = db.DateTimeProperty(auto_now_add = True) #datetime stamp of creation of user

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)


#code to create blog database
class TestPollDB3(db.Model):
	created = db.DateTimeProperty(auto_now_add = True)
	user = db.StringProperty(required = True)
	answer1 = db.IntegerProperty (required = True)
	answer2 = db.IntegerProperty (required = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

question1 = "Sample Question 1"
answers1 = ["Option 1", "Option 2", "Option 3"]
question2 = "Sample Question 2"
answers2 = ["Option 1", "Option 2", "Option 3"]

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **params):
		self.write(self.render_str(template, **params))


	#function to check that user's cookie contains valid user ID and hashed password
	def authenticate_user(self):
		visit_cookie_str = self.request.cookies.get('user')
		if visit_cookie_str:
			visitor_id = int(visit_cookie_str.split('|')[0])
			visitor_password = visit_cookie_str.split('|')[1]
			visitor = TestPoolUserDB.get_by_id(visitor_id)
			if visitor:
				if visitor_password == visitor.password:
					return True

	def user_logged_in(self):
		visit_cookie_str = self.request.cookies.get('user')
		visitor_id = int(visit_cookie_str.split('|')[0])
		visitor = TestPoolUserDB.get_by_id(visitor_id)
		return visitor.username

	def login(self):
		login_username = self.request.get("login_username")
		login_password = self.request.get("login_password")

		login_hashed_password = make_temp_password(login_password)

		user_check = db.GqlQuery("SELECT * FROM TestPoolUserDB WHERE username = :user", user=login_username)

		if user_check.get():
			for user in user_check:
				db_password = user.password #hashed password from user database
				db_id = user.key().id() #user ID from user database
			if login_hashed_password == db_password:
				#create cookie
				new_cookie = make_secure_val(db_id, login_password)
				#deliver cookie
				self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % new_cookie)
				self.redirect('/')
			else:
				self.render("usersignup.html", error = "Invalid password")
		else:
			self.render("usersignup.html", error = "Invalid username")


class MainPage(Handler):
	def get(self):
		if self.authenticate_user() == True:
			results = db.GqlQuery("SELECT * FROM TestPollDB3 ORDER BY created DESC")
			print "results pulled from database"
			answer1_results = [[],[],[]]
			answer2_results = [[],[],[]]
			answer1total = 0
			answer2total = 0
			for result in results:
				for x in range(3):
					if result.answer1 == x:
						answer1_results[x].append(result.user)
						answer1total += 1
					if result.answer2 == x:
						answer2_results[x].append(result.user)
						answer2total += 1

			self.render('results.html', question1=question1, question2=question2, answer1total=answer1total, answer2total=answer2total, answers1=answers2, answers2=answers2, answer1_results=answer1_results, answer2_results=answer2_results, logged_in=self.authenticate_user(), user=self.user_logged_in())
		else:
			self.redirect('/signup')


class Logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
		self.redirect("/signup")


class Signup(Handler):
	def get(self):
		self.render('usersignup.html')

	def post(self):
		if self.request.get("login_username") and self.request.get("login_password"):
			self.login()
		else:
			username = self.request.get("username")
			password = self.request.get("password")
			verify = self.request.get("verify")
			email = self.request.get("email")

			user_error = ""
			password_error = ""
			verify_error = ""
			email_error = ""

			if validate(username, USER_RE) == None:
				user_error = "That's not a valid username."
			if validate(password, PASSWORD_RE) == None:
				password_error = "That wasn't a valid password."
			if verify != password:
				verify_error = "Your passwords didn't match."
			if email and validate(email, EMAIL_RE) == None:
				email_error = "That's not a valid email."
			if user_error != "" or password_error != "" or verify_error != "" or email_error != "":
				self.render("usersignup.html", user_error = user_error,
							password_error = password_error,
							verify_error = verify_error,
							email_error = email_error,
							username = username,
							email = email)
			else:
				user_check = db.GqlQuery("SELECT * FROM TestPoolUserDB WHERE username = :user", user=username)
				if user_check.get():
					user_error = "This username is already being used."
					self.render("usersignup.html", user_error = user_error,
								password_error = password_error,
								verify_error = verify_error,
								email_error = email_error,
								username = "",
								email = email)
				else:
					hashed_password = make_temp_password(password)
					if email:
						new_user = TestPoolUserDB(username = username, password = hashed_password, email = email)
					else:
						new_user = TestPoolUserDB(username = username, password = hashed_password, email = "none")
					new_user.put()
					user_id = new_user.key().id()
					#create cookie
					new_cookie = make_secure_val(user_id, password)
					#deliver cookie
					self.response.headers.add_header('Set-Cookie', 'user=%s; Path=/' % new_cookie)
					self.redirect('/')


class TakePoll(Handler):
	def render_newpost(self, answer1="", answer2="", error="", user="", logged_in=False):
		self.render("poll.html", answer1=answer1, answer2=answer2, error=error, user=self.user_logged_in(), logged_in=self.authenticate_user())

	def post(self):
		if self.request.get("answer1") and self.request.get("answer2"):
			username = self.user_logged_in()
			user_check = db.GqlQuery("SELECT * FROM TestPoolUserDB WHERE username = :user", user=username)
			if user_check.get():
				self.redirect('/edit')
			else:
				answer1 = int(self.request.get("answer1"))
				answer2 = int(self.request.get("answer2"))
				print "answer 1 is %s" % answer1
				print "answer 2 is %s" % answer2
				user = self.user_logged_in()
				print "user is %s" % user

				if answer1 != "" and answer2 != "":
					print "answers again are %s and %s" % (answer1, answer2)
					current_entry = TestPollDB3(answer1=answer1, answer2=answer2, user=user)
					current_entry.put()
					time.sleep(0.1)
					print "poll posted successfully!"
					self.redirect('/')
		else:
			error = "You need to answer all questions!"
			self.render("poll.html", pollerror=error, user=self.user_logged_in(), logged_in=self.authenticate_user())

	def get(self):
		if self.authenticate_user() == True:
			self.render_newpost(logged_in=self.authenticate_user(), user=self.user_logged_in())
		else:
			self.redirect('/signup')



class Edit(TakePoll):
	def get(self):
		if self.authenticate_user() == True:
			self.render('editpoll.html', user=self.user_logged_in(), logged_in=self.authenticate_user())
		else:
			self.redirect('/signup')

	def post(self):
		if self.authenticate_user() == True:
			self.render('editpoll.html', user=self.user_logged_in(), logged_in=self.authenticate_user())
		else:
			self.redirect('/signup')




app = webapp2.WSGIApplication([('/', MainPage),
								('/takepoll', TakePoll),
								('/signup', Signup),
								('/logout', Logout),
								('/edit', Edit)
								],
								debug=True)
