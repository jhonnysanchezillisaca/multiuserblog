import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import time

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


# TODO: Use correct types in the Model (foreign Keys)
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
    content = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post = db.StringProperty(required=True)


class Like(db.Model):
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

        # Get the likes of the post
        q1 = Like.gql("WHERE post = :post_id", post_id=blog_id, keys_only=True)
        likes = len(q1.fetch(None))

        like = "Like"
        for l in q1:
            if l.creator == username:
                like = "Unlike"

        # Check if the post belongs to the current user
        isUserPost = False
        if post.creator == username:
            isUserPost = True

        # Handles error messages
        comment_error = self.request.get("c_err")
        like_error = self.request.get("l_err")
        error = self.request.get("err")

        self.render("post.html", post=post, comments=post_comments,
                    isUserPost=isUserPost, blog_id=blog_id, username=username,
                    likes=likes, error=error, like_error=like_error,
                    comment_error=comment_error, like=like)

    def post(self, blog_id):
        comment_error = ''
        username = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))

        if(username):
            content = self.request.get("comment-content")
            # Like form submited
            if(self.request.get("form_name") == "like"):
                q = Like.gql("WHERE creator = :username and post = :post",
                             username=username, post=blog_id)
                like = q.get()
                # User can't like its own post
                if username == post.creator:
                    self.redirect("/post/%d?l_err=You can't like your own post" % int(blog_id))  # NOQA
                # Unlike post
                elif len(q.fetch(None)) > 0:
                    like.delete()
                    # Sleep to give time to the DB to achieve consistency
                    time.sleep(0.1)
                    self.redirect("/post/%d" % (int(blog_id)))
                # Like created and stored
                else:
                    new_like = Like(creator=username, post=blog_id)
                    new_like.put()
                    time.sleep(0.1)
                    self.redirect("/post/%d" % (int(blog_id)))
            # Comment form submited
            elif self.request.get("form_name") == "comment" and content:
                new_comment = Comment(content=content,
                                      post=blog_id, creator=username)
                new_comment.put()
                # Sleep to give time to the DB to achieve consistency
                time.sleep(0.1)
                self.redirect("/post/%d" % (int(blog_id)))
            else:
                self.redirect("/post/%d?c_err=Comment can't be empty" % (int(blog_id)))  # NOQA

        else:
            self.redirect("/post/%d?err=You need to be logged in to perform that action" % int(blog_id))  # NOQA


class NewPostPage(Handler):
    def get(self):
        active_user = self.activeUser()
        if(active_user):
            self.render("new_post.html", post=None)
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
            # Sleep to give time to the DB to achieve consistency
            time.sleep(0.1)
            # Redirect to a page with the post
            self.redirect("/post/%d" % (blog_post.key().id()))
        # If error, stays in the new_post page and render the error messages
        error = "We need a subject and the content!"
        self.render("new_post.html", subject=subject, content=content,
                    error=error)


class EditPostPage(Handler):
    def get(self, blog_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))
        if(active_user and post.creator == active_user):
            self.render("new_post.html", post=post, subject=post.subject,
                        content=post.content, blog_id=blog_id)
        else:
            self.redirect("/login")

    def post(self, blog_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))

        if(active_user and post.creator == active_user):
            subject = self.request.get("subject")
            content = self.request.get("content")
            if(subject and content):
                post.subject = subject
                post.content = content
                post.put()
            # Sleep to give time to the DB to achieve consistency
            time.sleep(0.1)
            self.redirect("/post/%d" % (int(blog_id)))
        else:
            self.redirect("/login")


class DeletePostPage(Handler):
    def get(self, blog_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))
        if(active_user and post.creator == active_user):
            # renders the post
            self.render("delete_post.html", post=post)
        else:
            self.redirect("/login")

    def post(self, blog_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(blog_id))
        if(active_user and post.creator == active_user):
            # Deletes the likes of the post
            q = Like.gql("WHERE post = :post_ID", post_ID=blog_id)
            for l in q:
                l.delete()
            # Deletes the comments of the post
            q = Comment.gql("WHERE post = :post_ID", post_ID=blog_id)
            for c in q:
                c.delete()
            # Delete the post
            post.delete()
            # Sleep to give time to the DB to achieve consistency
            time.sleep(0.1)
            self.redirect("/welcome")
        else:
            self.redirect("/login")


class EditCommentPage(Handler):
    def get(self, comment_id):
        active_user = self.activeUser()
        comment = Comment.get_by_id(int(comment_id))
        post = BlogPost.get_by_id(int(comment.post))
        if(active_user and comment.creator == active_user):
            # renders the post and the comment form to edit
            self.render("edit_comment.html", comment=comment,
                        post=post, comment_id=comment_id)
        else:
            self.redirect("/login")

    def post(self, comment_id):
        active_user = self.activeUser()
        comment = Comment.get_by_id(int(comment_id))
        post = BlogPost.get_by_id(int(comment.post))

        if(active_user and comment.creator == active_user):
            new_content = self.request.get("comment-content")
            if new_content:
                comment.content = new_content
                comment.put()
            # Sleep to give time to the DB to achieve consistency
            time.sleep(0.1)
            self.redirect("/post/%d" % (int(post.key().id())))
        else:
            self.redirect("/login")


class DeleteCommentPage(Handler):
    def get(self, comment_id):
        active_user = self.activeUser()
        comment = Comment.get_by_id(int(comment_id))
        post = BlogPost.get_by_id(int(comment.post))
        if(active_user and comment.creator == active_user):
            # renders the post and the comment form to edit
            self.render("delete_comment.html", comment=comment,
                        post=post, comment_id=comment_id)
        else:
            self.redirect("/login")

    def post(self, comment_id):
        active_user = self.activeUser()
        comment = Comment.get_by_id(int(comment_id))
        post = BlogPost.get_by_id(int(comment.post))

        if(active_user and comment.creator == active_user):
            comment.delete()
            # Sleep to give time to the DB to achieve consistency
            time.sleep(0.1)
            self.redirect("/post/%d" % (int(post.key().id())))
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
    ('/editcomment/(\d+)', EditCommentPage),
    ('/deletecomment/(\d+)', DeleteCommentPage),
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
