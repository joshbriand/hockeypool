from google.appengine.ext import ndb

# code to create user table


class TestUsers21(ndb.Model):
    username = ndb.StringProperty(required=True)  # username
    password = ndb.StringProperty(required=True)  # hashed password
    # datetime stamp of creation of user
    created = ndb.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# code to create question table
class TestQuestions21(ndb.Model):
    question = ndb.StringProperty(required=True)
    options = ndb.StringProperty(repeated=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class TestResults21(ndb.Model):
    choice = ndb.StringProperty()
    question = ndb.StringProperty()
    user = ndb.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


def blog_key(blog_name):
    '''code to create key for blog, so site can use strong consistency, code
    came from Google's solution to their guestbook tutorial'''
    return ndb.Key('Blog', blog_name)
