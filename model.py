from google.appengine.ext import ndb
from google.appengine.ext import db
import time


# TODO: document create methods returns id
# TODO: Use correct types in the Model (foreign Keys)
class BlogPost(ndb.Model):
    # post_ID = db.StringProperty(required=True)
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    creator = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    likes = ndb.IntegerProperty(required=False)

    def editPost(self, subject, content):
        self.subject = subject
        self.content = content
        self.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)

    def deletePost(self):
        self.key.delete()
        time.sleep(0.1)

    @classmethod
    def getPosts(cls, numPosts):
        # q = ndb.gql("select * from BlogPost order by created desc")
        # return q.fetch(numPosts)
        q = cls.query().order(-BlogPost.created)
        return q.fetch(numPosts)

    @classmethod
    def createPost(cls, creator, subject, content):
        blog_post = BlogPost(subject=subject, content=content,
                             creator=creator)
        blog_post.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)
        return blog_post.key.id()


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    h_password = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=False)
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def createUser(cls, username, h_password, email):
        new_user = User(username=username,
                        h_password=h_password,
                        email=email)
        new_user.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)

    @classmethod
    def username_exists(cls, username):
        q = cls.query(cls.username == username)
        if q.get():
            return True
        return False

    @classmethod
    def valid_login(cls, username, h_password):
        if cls.username_exists(username):
            q = cls.query(cls.username == username)
            result = q.get()
            if result.h_password == h_password:
                return True
        return False


class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    creator = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    post = ndb.StringProperty(required=True)

    def editComment(self, content):
        self.content = content
        self.put()
        time.sleep(0.1)

    def deleteComment(self):
        self.key.delete()
        time.sleep(0.1)

    @classmethod
    def getAllComments(cls, post_id):
        # Get comments of the post
        q = cls.query()
        return q.filter(cls.post == str(post_id)).order(-cls.created)

    @classmethod
    def createComment(cls, creator, post, content):
        new_comment = Comment(content=content,
                              post=post, creator=creator)
        new_comment.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)
        return new_comment.key.id()

    @classmethod
    def deleteCommentsFromPost(cls, post_id):
        # Deletes the comments of the post
        q = cls.query(cls.post == post_id)
        # q = Comment.gql("WHERE post = :post_id", post_id=post_id)
        for c in q:
            c.key.delete()


class Like(ndb.Model):
    creator = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    post = ndb.StringProperty(required=True)

    @classmethod
    def getLikes(cls, post_id):
        q = cls.query(cls.post == post_id)
        # q = cls.gql("WHERE post = :post_id", post_id=post_id, keys_only=True)
        return len(q.fetch(None))

    @classmethod
    def userLikedPost(cls, username, post_id):
        q = cls.query(cls.post == post_id, cls.creator == username)
        # q = Like.gql("WHERE post = :post_id and creator = :creator",
        #              post_id=post_id, creator=username, keys_only=True)
        if(len(q.fetch(None)) > 0):
            return True
        return False

    @classmethod
    def deleteLike(cls, creator, post_id):
        q = cls.query(cls.creator == creator, cls.post == post_id)
        # q = Like.gql("WHERE creator = :creator and post = :post",
        #              creator=creator, post=post)
        q.get().key.delete()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)

    @classmethod
    def createLike(cls, creator, post):
        new_like = Like(creator=creator, post=post)
        new_like.put()
        # Sleep to give time to the DB to achieve consistency
        time.sleep(0.1)
        return new_like.key.id()

    @classmethod
    def deleteLikesFromPost(cls, post_id):
        # Deletes the likes of the post
        q = cls.query(cls.post == post_id)
        # q = Like.gql("WHERE post = :post_id", post_id=post_id)
        for l in q:
            l.key.delete()
