#To do
# - break into modules
from tables import TestUsers21, TestResults21, TestQuestions21, blog_key
import handlers
from google.appengine.ext import ndb


app = handlers.webapp2.WSGIApplication([('/logout', handlers.Logout),
                               ('/', handlers.Results),
                               ('/takepoll', handlers.TakePoll),
                               ('/edit', handlers.Edit),
                               ('/addquestion', handlers.AddQuestion),
                               ('/deletequestion', handlers.DeleteQuestion),
                               ('/adduser', handlers.AddUser),
                               ('/deleteuser', handlers.DeleteUser)
                               ],
                              debug=True)
