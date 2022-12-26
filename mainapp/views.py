from django.shortcuts import render, redirect
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.contrib import messages

# Create your views here.
# in this program 'email' is taken as 'username' and 'name ' is taken as 'first_name'


def index(request):
    return render(request, 'index.html')


def signup(request):
    if request.method == "POST":
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if name and email and password:
            if password == confirm_password:
                if User.objects.filter(email=email).exists():
                    messages.info(request, 'Email already in use')
                    return redirect('signup')
                else:
                    user = User.objects.create_user(
                        username=email, first_name=name, email=email, password=password)
                    user.save()
                    return redirect('login')
            else:
                messages.info(request, 'Passwords not matched!')
                return redirect('signup')
        else:
            if not name:
                messages.info(request, 'Enter username')
                return redirect('signup')
            if not email:
                messages.info(request, 'Enter email')
                return redirect('signup')
            if not password:
                messages.info(request, 'Enter password')
                return redirect('signup')
    else:
        return render(request, 'signup.html')


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = auth.authenticate(username=email, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('/')
        else:
            messages.info(request, 'Credentials Invalid')
            return redirect('login')
    else:
        return render(request, 'login.html')


def logout(request):
    auth.logout(request)
    return redirect('/')



def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "password_reset_email.txt"
                    c = {
                        "email": user.email,
                        'domain': '127.0.0.1:8000',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'admin@example.com',
                                  [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')

                    # messages.success(request, 'A message with reset password instructions has been sent to your inbox.')
                    return redirect("/")
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="password_reset.html", context={"password_reset_form": password_reset_form})
