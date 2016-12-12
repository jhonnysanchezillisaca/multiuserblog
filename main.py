import os
import webapp2
import jinja2
import re
import hashlib
import hmac

from google.appengine.ext import db

SECRET = 'imsosecret'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **params):
        self.response.out.write(*a, **params)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        self.write(self.render_str(template, **params))

    def activeUser(self):
        active_user = None
        if (self.request.cookies.get('username')):
            active_user = check_secure_val(self.request.cookies.
                                           get('username'))
        return active_user


class BlogPost(db.Model):
    # post_ID = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(required=False)


class User(db.Model):
    username = db.StringProperty(required=True)
    h_password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)


class Comment(db.Model):
    content = db.StringProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post = db.StringProperty(required=True)


class MainPage(Handler):
    def get(self):
        if(self.activeUser()):
            self.redirect("/welcome")

        q = db.GqlQuery("select * from BlogPost order by created desc")
        posts = q.fetch(10)
        self.render("blog.html", posts=posts)


class PostPage(Handler):
    def get(self, blog_id):
        # Get the post to show
        post = BlogPost.get_by_id(int(blog_id))
        # Get current username
        username = self.activeUser()

        # Get comments of the post
        q = Comment.all()
        post_comments = q.filter('post =', str(blog_id)).order('-created')

        # Check if the post belongs to the current user
        isUserPost = False
        if post.creator == username:
            isUserPost = True

        self.render("post.html", posts=[post], comments=post_comments,
                    isUserPost=isUserPost, blog_id=blog_id, username=username)

    def post(self, blog_id):
        comment_error = ''
        username = self.activeUser()
        if(username):
            content = self.request.get("comment-content")
            if content:
                new_comment = Comment(content=content,
                                      post=blog_id, creator=username)
                new_comment.put()
            else:
                self.redirect("/login")
        else:
            comment_error = "You need to be logged in to add comments"
        # TODO: Bug, the comment is created, but don't shows up until refresh
        self.redirect("/post/%d" % (int(blog_id)))


class NewPostPage(Handler):
    def get(self):
        active_user = self.activeUser()
        if(active_user):
            self.render("new_post.html")
        else:
            self.redirect("/login")

    def post(self):
        active_user = self.activeUser()
        # If the user cookie is not valid redirect to main page
        if(not active_user):
            self.redirect("/")
        subject = self.request.get("subject")
        content = self.request.get("content")
        # Save post to DB
        if(subject and content):
            blog_post = BlogPost(subject=subject, content=content,
                                 creator=active_user)
            blog_post.put()
            # Redirect to a page with the post
            self.redirect("/post/%d" % (blog_post.key().id()))
        # If error stays in the new_post page and render the error messages
        error = "We need a subject and the content!"
        self.render("new_post.html", subject=subject, content=content,
                    error=error)


class EditPostPage(Handler):
    def get(self, blog_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))
        if(active_user and post.creator == active_user):
            self.render("new_post.html", post=post, blog_id=blog_id)
        else:
            self.redirect("/login")

    def post(self, blog_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))
        if(active_user and post.creator == active_user):
            subject = self.request.get("subject")
            content = self.request.get("content")
            post.subject = subject
            post.content = content
            post.put()
            self.redirect("/post/%d" % (int(blog_id)))
        self.redirect("/login")


class DeletePostPage(Handler):
    def get(self, blog_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))
        if(active_user and post.creator == active_user):
            post.delete()
            self.redirect("/welcome")
        else:
            self.redirect("/login")


class SignupPage(Handler):
    def get(self):
        active_user = self.activeUser()
        if(active_user):
            self.redirect("/welcome")
        self.render("sign_up.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        # Check if the data is valid and store in the DB
        if (all_valid(username, password, verify, email) and
                not username_exists(username)):
            new_user = User(username=username,
                            h_password=hash_password(password),
                            email=email)
            new_user.put()
            # Set a cookie with the username value secured
            self.response.set_cookie('username', make_secure_val(username))
            self.redirect("/welcome")
        # Render the errors if any
        else:
            if username_exists(username):
                username_error = "Username already exists"
            if not valid_username(username):
                username_error = "That's not a valid username."
            if not valid_password(password):
                password_error = "That wasn't a valid password."
            if not valid_verify(password, verify):
                verify_error = "Your passwords didn't match."
            if not valid_email(email):
                email_error = "That's not a valid email."

            self.render("sign_up.html", username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error, email_error=email_error,
                        username=username, email=email)


class WelcomePage(Handler):
    def get(self):
        username = self.activeUser()
        if username:
            q = db.GqlQuery("select * from BlogPost order by created desc")
            posts = q.fetch(10)
            for p in posts:
                print p.key().id()
            self.render("welcome.html", username=username, posts=posts)
        else:
            self.redirect("login")


class LoginPage(Handler):
    def get(self):
        active_user = self.activeUser()
        if(active_user):
            self.redirect("/welcome")
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        login_error = ''

        if valid_login(username, password):
            self.response.set_cookie('username', make_secure_val(username))
            self.redirect('welcome')
        login_error = "Invalid login"
        self.render("login.html", login_error=login_error)


class LogoutPage(Handler):
    def get(self):
        self.response.delete_cookie('username')
        self.redirect("/")


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', NewPostPage),
    ('/login', LoginPage),
    ('/logout', LogoutPage),
    ('/signup', SignupPage),
    ('/welcome', WelcomePage),
    ('/post/(\d+)', PostPage),
    ('/editpost/(\d+)', EditPostPage),
    ('/deletepost/(\d+)', DeletePostPage),
], debug=True)


def set_cookie(self, name, val):
    self.response.set_cookie(name, make_secure_val(val))


def username_exists(username):
    q = User.all()
    q.filter('username =', username)
    if q.get():
        return True
    return False


def valid_login(username, password):
    if username_exists(username):
        q = User.all()
        q.filter('username =', username)
        result = q.get()
        if result.h_password == hash_password(password):
            return True
    return False


# Check sign up
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def all_valid(username, password, verify, email):
    return (valid_username(username) and valid_password(password) and
            valid_email(email) and valid_verify(password, verify))


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASS_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email) or email == ""


def valid_verify(password, verify):
    if password == verify:
        return True
    return False


# Utils password
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s,%s" % (s, hash_str(s))


def hash_password(s):
    return hash_str(s)


# Returns the hash of the password if the hash with the secret is correct
def check_secure_val(h):
    (s, h) = h.split(',')
    if(hash_str(s) == h):
        return s
    return None
