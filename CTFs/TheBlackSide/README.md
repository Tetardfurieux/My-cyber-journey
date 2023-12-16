# The black side writeup
## Google Bot Center
User-Agent is the key to the flag

    Host: www.example.com
    Connection: keep-alive
    Accept: text/plain,text/html,*/*
    User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
    Accept-Encoding: gzip,deflate,br

## Code Snippet 1
    require "roda"
    
    class App < Roda
      plugin :render
      plugin :public
      plugin :assets, css: 'bulma.min.css'
    
      route do |r|
        r.assets
        r.public
        r.root do
          render('home')
        end
        r.get 'acceis' do
          @base_url = 'https://www.acceis.fr'
          if r.params['redirect_url'].nil?
            r.redirect '/'
          (1)elsif /\A#{Regexp.escape(@base_url)}\/.*\Z/.match?(r.params['redirect_url'])
            r.redirect r.params['redirect_url']
          (2)elsif /\A#{@base_url}\/.*\Z/.match?(r.params['redirect_url'])
            response.write ENV['FLAG_1']
            r.redirect r.params['redirect_url']
          (3)elsif /^#{Regexp.escape(@base_url)}\/.*$/.match?(r.params['redirect_url'])
            response.write ENV['FLAG_2']
            r.redirect r.params['redirect_url']
          (4)elsif /\A#{Regexp.escape(@base_url)}\/.*\Z/i.match?(r.params['redirect_url'])
            response.write ENV['FLAG_3']
            r.redirect r.params['redirect_url']
          else
            r.redirect 'https://www.acceis.fr/rejoignez-nous/'
          end
        end
      end
    end
URL: http://snippet1.tbsctf.fr/acceis?redirect_url=https://www.acceis.fr/
### First flag
We can see that the difference between (1) and (2) is that the base_url is not escaped for (2). <br>
Escaping means forcing every char to be considered as a string, especially special characters. Meaning that '? / ! . < >' will be replaced by '\? \/ \! \. \< \>'.<br>
Then (1) gives the following regex: https:\/\/www\.acceis\.fr\/.*\Z/ <br>
Whereas (2) gives: https://www.acceis.fr\/.*\Z/<br>
This means that the "." are considered as "match any character except \n". <br>
Now we understand that we have to replace them by something else that "." to bypass (1), however removing the second "." will create an invalid URL, so we only replace the first ".". <br>

    curl http://snippet1.tbsctf.fr/acceis?redirect_url=https://wwwaacceis.fr/
<details>
<summary>Voir le flag :</summary>
    
***TBS{11_f4u7_éch4pp3r_13_p01n7}***
</details>

### Second flag
(3) Regex is: https:\/\/www\.acceis\.fr\/.*$/ <br>
We can see that the "\Z" disappeared and that "$" appeared. The "$" means that it has to be at the end of the string. <br>
"\Z" means "matches the end of the string unless the string ends with a "\n", in which case it matches just before the "\n"" <br>
The idea is then to insert a "\n" in the URL and then match the regex. This way we bypass (1) since it matches before the "\n" <br>
We have to URL encore "\n" or it will not act as an end of line : %0A

    curl http://snippet1.tbsctf.fr/acceis?redirect_url=%0Ahttps://www.acceis.fr/
<details>
<summary>Voir le flag :</summary>
    
***TBS{m0d1f13ur5_37_dé11m173ur5}***
</details>

### Third flag
(4) Regex is https:\/\/www\.acceis\.fr\/.*\Z/ <br>
It is exactly the same one as (1) but with the "i" flag with means "case insensitive"

    curl http://snippet1.tbsctf.fr/acceis?redirect_url=https://www.Acceis.fr/
<details>
<summary>Voir le flag :</summary>
    
***TBS{7u_c0nn415_Un1c0d3_0o68l?}***
</details>
