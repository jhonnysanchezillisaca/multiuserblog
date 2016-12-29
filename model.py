from google.appengine.ext import db
import time


# TODO: document create methods returns id
# TODO: Use correct types in the Model (foreign Keys)
class BlogPost(db.Model):
    # post_ID = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(required=False)

    def editPost(self, subject, content):
        self.subject = subject
        self.content = content
        self.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)

    def deletePost(self):
        self.delete()
        time.sleep(0.1)

    @staticmethod
    def getPosts(numPosts):
        q = db.GqlQuery("select * from BlogPost order by created desc")
        return q.fetch(numPosts)

    @staticmethod
    def createPost(creator, subject, content):
        blog_post = BlogPost(subject=subject, content=content,
                             creator=creator)
        blog_post.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)
        return blog_post.key().id()


class User(db.Model):
    username = db.StringProperty(required=True)
    h_password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)

    @staticmethod
    def createUser(username, h_password, email):
        new_user = User(username=username,
                        h_password=h_password,
                        email=email)
        new_user.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)

    @staticmethod
    def username_exists(username):
        q = User.all()
        q.filter('username =', username)
        if q.get():
            return True
        return False

    @staticmethod
    def valid_login(username, h_password):
        if User.username_exists(username):
            q = User.all()
            q.filter('username =', username)
            result = q.get()
            if result.h_password == h_password:
                return True
        return False


class Comment(db.Model):
    content = db.TextProperty(required=True)
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post = db.StringProperty(required=True)

    def editComment(self, content):
        self.content = content
        self.put()
        time.sleep(0.1)

    def deleteComment(self):
        self.delete()

    @staticmethod
    def getAllComments(blog_id):
        # Get comments of the post
        q = Comment.all()
        return q.filter('post =', str(blog_id)).order('-created')

    @staticmethod
    def createComment(creator, post, content):
        new_comment = Comment(content=content,
                              post=post, creator=creator)
        new_comment.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)
        return new_comment.key().id()

    @staticmethod
    def deleteCommentsFromPost(post_id):
        # Deletes the comments of the post
        q = Comment.gql("WHERE post = :post_id", post_id=post_id)
        for c in q:
            c.delete()


class Like(db.Model):
    creator = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post = db.StringProperty(required=True)

    @staticmethod
    def getLikes(blog_id):
        q = Like.gql("WHERE post = :post_id", post_id=blog_id, keys_only=True)
        return len(q.fetch(None))

    @staticmethod
    def userLikedPost(username, blog_id):
        q = Like.gql("WHERE post = :post_id and creator = :creator",
                     post_id=blog_id, creator=username, keys_only=True)
        if(len(q.fetch(None)) > 0):
            return True
        return False

    @staticmethod
    def deleteLike(creator, post):
        q = Like.gql("WHERE creator = :creator and post = :post",
                     creator=creator, post=post)
        q.get().delete()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)

    @staticmethod
    def createLike(creator, post):
        new_like = Like(creator=creator, post=post)
        new_like.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)
        return new_like.key().id()

    @staticmethod
    def deleteLikesFromPost(post_id):
        # Deletes the likes of the post
        q = Like.gql("WHERE post = :post_id", post_id=post_id)
        for l in q:
            l.delete()
