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






class TakePoll(Handler):
	def render_newpost(self, answer1="", answer2="", error="", user="", logged_in=False):
		self.render("poll.html", answer1=answer1, answer2=answer2, error=error, user=self.user_logged_in(), logged_in=self.authenticate_user())

	def post(self):
		if self.request.get("answer1") and self.request.get("answer2"):
			username = self.user_logged_in()
			user_check = db.GqlQuery("SELECT * FROM Users WHERE username = :user", user=username)
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

class Signup(Handler):
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
                self.render("usersignup.html", user_error=user_error,
                            password_error=password_error,
                            verify_error=verify_error,
                            username=username,
                            email=email,
                            admin=self.admin_logged_in())
            else:
                user_check = db.GqlQuery(
                    "SELECT * FROM TestUsers21 WHERE username = :user",
                    user=username)
                if user_check.get():
                    user_error = "This username is already being used."
                    self.render("usersignup.html", user_error=user_error,
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
                    user_id = new_user.key().id()
                    # create cookie
                    new_cookie = make_secure_val(user_id, password)
                    # deliver cookie
                    self.response.headers.add_header(
                        'Set-Cookie', 'user=%s; Path=/' %
                        new_cookie)
                    self.redirect('/')







app = webapp2.WSGIApplication([('/', MainPage),
								('/takepoll', TakePoll),
								('/signup', Signup),
								('/logout', Logout),
								('/edit', Edit)
								],
								debug=True)
