import os
import webapp2
import jinja2
import re
import hashlib
import hmac
from model import BlogPost, User, Comment, Like

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

    # Return the active user if it exists, else return None
    def activeUser(self):
        active_user = None
        if (self.request.cookies.get('username')):
            active_user = check_secure_val(self.request.cookies.
                                           get('username'))
        return active_user


class MainPage(Handler):
    def get(self):
        if(self.activeUser()):
            return self.redirect("/welcome")
        # Get posts order by creation date
        posts = BlogPost.getPosts(10)
        self.render("blog.html", posts=posts)


class PostPage(Handler):
    def get(self, post_id):
        # Get the post to show
        post = BlogPost.get_by_id(int(post_id))
        # If the post didn't exists returns to the main page
        if not post:
            return self.redirect("/")
        # Get current username
        active_user = self.activeUser()

        # Get comments of the post
        post_comments = Comment.getAllComments(post_id)

        # Get the likes of the post
        likes = Like.getLikes(post_id)

        # Establish text of button to 'Like' or 'Unlike' as needed
        like = "Unlike" if Like.userLikedPost(active_user, post_id) else "Like"

        # Check if the post belongs to the current user
        isUserPost = True if post.creator == active_user else False

        # Handles error messages
        comment_error = self.request.get("c_err")
        like_error = self.request.get("l_err")
        error = self.request.get("err")

        self.render("post.html", post=post, comments=post_comments,
                    isUserPost=isUserPost, post_id=post_id,
                    username=active_user, likes=likes, error=error,
                    like_error=like_error, comment_error=comment_error,
                    like=like)

    def post(self, post_id):
        comment_error = ''
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(post_id))

        if(active_user):
            content = self.request.get("comment-content")
            # Like form submited
            if(self.request.get("form_name") == "like"):
                # User can't like its own post
                if active_user == post.creator:
                    return self.redirect("/post/%d?l_err=You can't like your own post" % int(post_id))  # NOQA
                # Unlike post
                elif Like.userLikedPost(active_user, post_id):
                    Like.deleteLike(active_user, post_id)
                    return self.redirect("/post/%d" % (int(post_id)))
                # Like created and stored
                else:
                    Like.createLike(active_user, post_id)
                    return self.redirect("/post/%d" % (int(post_id)))
            # Comment form submited and content is not empty
            elif self.request.get("form_name") == "comment" and content:
                Comment.createComment(active_user, post_id, content)
                return self.redirect("/post/%d" % (int(post_id)))
            else:
                return self.redirect("/post/%d?c_err=Comment can't be empty"
                                     % (int(post_id)))

        else:
            login_error = "You must be logged in to perform that action"
            self.render("login.html", login_error=login_error)


class NewPostPage(Handler):
    def get(self):
        active_user = self.activeUser()
        if(active_user):
            return self.render("new_post.html", post=None)
        else:
            return self.redirect("/login")

    def post(self):
        active_user = self.activeUser()
        # If the user cookie is not valid redirect to the login page
        if(not active_user):
            return self.redirect("/login")
        subject = self.request.get("subject")
        content = self.request.get("content")
        # Save post to DB
        if(subject and content):
            post_id = BlogPost.createPost(active_user, subject, content)
            # Redirect to a page with the post
            return self.redirect("/post/%d" % (post_id))
        # If error, stays in the new_post page and render the error messages
        error = "We need a subject and the content!"
        self.render("new_post.html", subject=subject, content=content,
                    error=error)


class EditPostPage(Handler):
    def get(self, post_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(post_id))
        if(active_user and post.creator == active_user):
            self.render("new_post.html", post=post, subject=post.subject,
                        content=post.content, post_id=post_id)
        else:
            return self.redirect("/login")

    def post(self, post_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(post_id))

        if(active_user and post.creator == active_user):
            subject = self.request.get("subject")
            content = self.request.get("content")
            if(subject and content):
                post.editPost(subject, content)
            return self.redirect("/post/%d" % (int(post_id)))
        else:
            return self.redirect("/login")


class DeletePostPage(Handler):
    def get(self, post_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(post_id))
        if(active_user and post.creator == active_user):
            # renders the post
            self.render("delete_post.html", post=post)
        else:
            return self.redirect("/login")

    def post(self, post_id):
        active_user = self.activeUser()
        post = BlogPost.get_by_id(int(post_id))
        if(active_user and post.creator == active_user):
            # Deletes the likes of the post
            Like.deleteLikesFromPost(post_id)
            # Deletes the comments of the post
            Comment.deleteCommentsFromPost(post_id)
            # Delete the post
            post.deletePost()
            return self.redirect("/welcome")
        else:
            return self.redirect("/login")


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
            return self.redirect("/login")

    def post(self, comment_id):
        active_user = self.activeUser()
        comment = Comment.get_by_id(int(comment_id))
        post = BlogPost.get_by_id(int(comment.post))

        if(active_user and comment.creator == active_user):
            new_content = self.request.get("comment-content")
            if new_content:
                comment.editComment(new_content)
            return self.redirect("/post/%d" % (int(post.key.id())))
        else:
            return self.redirect("/login")


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
            return self.redirect("/login")

    def post(self, comment_id):
        active_user = self.activeUser()
        comment = Comment.get_by_id(int(comment_id))
        post = BlogPost.get_by_id(int(comment.post))

        if(active_user and comment.creator == active_user):
            comment.deleteComment()
            return self.redirect("/post/%d" % (int(post.key.id())))
        else:
            return self.redirect("/login")


class SignupPage(Handler):
    def get(self):
        active_user = self.activeUser()
        if(active_user):
            return self.redirect("/welcome")
        else:
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
                not User.username_exists(username)):
            User.createUser(username=username,
                            h_password=hash_password(password),
                            email=email)
            # Set a cookie with the username value secured
            self.response.set_cookie('username', make_secure_val(username))
            return self.redirect("/welcome")
        # Render the errors if any
        else:
            if User.username_exists(username):
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
            posts = BlogPost.getPosts(10)
            self.render("welcome.html", username=username, posts=posts)
        else:
            return self.redirect("login")


class LoginPage(Handler):
    def get(self):
        active_user = self.activeUser()
        if(active_user):
            return self.redirect("/welcome")
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        login_error = ''

        if User.valid_login(username, hash_password(password)):
            self.response.set_cookie('username', make_secure_val(username))
            return self.redirect('welcome')
        else:
            login_error = "Invalid login"
            self.render("login.html", login_error=login_error)


class LogoutPage(Handler):
    def get(self):
        self.response.delete_cookie('username')
        return self.redirect("/")


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
