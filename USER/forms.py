
from wtforms import Form, StringField, IntegerField, TextAreaField, PasswordField,validators

#User registration form
class RegisterForm(Form):
    username = StringField('Username', [validators.Length(min=6,max=25)])
    password = PasswordField('Password',[validators.DataRequired(),validators.EqualTo('confirm',message='and confirm Password do not match.'),validators.Length(min=6,max=12)])
    confirm = PasswordField('Confirm Password')
    public_key = TextAreaField('public_key', [validators.Length(min=50)])

class TransactionForm(Form):
    sender_public_key = TextAreaField('sender_public_key', [validators.Length(min=1,message='Check the sender public key and enter again.')])
    sender_private_key = TextAreaField('sender_private_key', [validators.Length(min=1,message='Check the sender private key and enter again.')])
    recipient_public_key = TextAreaField('recipient_public_key', [validators.Length(min=1,message='Check the recipient public key and enter again.')])
    amount = IntegerField('amount', [validators.NumberRange(min=1,message='Check the amount and enter again.')])

class BuyForm(Form):
    my_public_key = TextAreaField('my_public_key', [ validators.Length(min=1, message='Check the sender public key and enter again.')])
    my_private_key = TextAreaField('my_private_key', [validators.Length(min=1, message='Check the sender private key and enter again.')])
    amount = IntegerField('amount', [validators.NumberRange(min=1, message='Check the amount and enter again.')])

class backupForm(Form):
    backup_public_key = TextAreaField('backup_public_key', [validators.Length(min=1,message='Check the sender public key and enter again.')])
    backup_private_key = TextAreaField('backup_private_key', [validators.Length(min=1,message='Check the sender private key and enter again.')])
    backup_key = TextAreaField('backup_key', [validators.Length(min=1,message='Check the sender private key and enter again.')])

class recoverform(Form):
    new_public_key = TextAreaField('new_public_key', [validators.Length(min=1,message='Check the sender public key and enter again.')])
    new_private_key = TextAreaField('new_private_key', [validators.Length(min=1,message='Check the sender private key and enter again.')])
    old_public_key = TextAreaField('old_public_key', [validators.Length(min=1,message='Check the recipient public key and enter again.')])
    recover_key = TextAreaField('recover_key', [validators.Length(min=1,message='Check the recipient public key and enter again.')])
