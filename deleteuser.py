from tacochooseday import Handler

class DeleteUser(Handler):
    def get(self):
        if self.user_logged_in() == "admin":
            users = ndb.gql("SELECT * FROM TestUsers21 WHERE ANCESTOR is :ancestor",
            ancestor = blog_key(DEFAULT_BLOG_NAME))
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
            deleteQuery = ndb.gql("SELECT * FROM TestUsers21 WHERE username = :user AND ANCESTOR is :ancestor",
            user=deleteUsername, ancestor = blog_key(DEFAULT_BLOG_NAME))
            deleteUser = deleteQuery.get()
            deleteUser.key.delete()
            print "user deleted"
            deleteResults = ndb.gql("SELECT * FROM TestResults21 WHERE user = :user AND ANCESTOR is :ancestor",
            user=deleteUsername, ancestor = blog_key(DEFAULT_BLOG_NAME))
            for deleteResult in deleteResults:
                deleteResult.key.delete()
                print "result deleted"
            self.redirect('/')
        else:
            self.redirect('/logout')
