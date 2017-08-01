#!/usr/bin/perl
#   Author: Alan M. Makoev
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


# This script creates rules for Spamassassin (http://spamassassin.apache.org)
# that should bounce out russian spam. The rules are generated for the set
# of tokens read from the $TOKENS_FILE. The tokens are expected to be in utf-8
# encoding.

# The is intended to be "byte-oriented" instead of "char-oriented".

no utf8;
use bytes;
use POSIX qw(setlocale LC_ALL LC_CTYPE);

# The perllocale.html states:
# "eq and ne are unaffected by locale: they always perform a char-by-char
# comparison of their scalar operands"
# "Regular expressions and case-modification functions (uc(), lc(), ucfirst(),
# and lcfirst()) use LC_CTYPE"

setlocale( LC_ALL, "C" );
setlocale( LC_TYPE, "C" );

# The following procedure is based on Convert::Cyrillic package by John
# Neystadt <http://www.neystadt.org/john/>. Unfortunately, the procedure
# Convert::Cyrillic:cstocs did not work on my perl 5.8, because it uses
# UTF-8 for character representation and does not recognise cyrillic chars
# in single-byte encodings. Thus the "tr///" operator leaves original string
# intact.

@{char_tab{'UTF8'}} = ["Ð","Ð‘","Ð’","Ð“","Ð”","Ð•","Ð","Ð–","Ð—","Ð˜","Ð™","Ðš","Ð›","Ðœ","Ð","Ðž","ÐŸ","Ð ","Ð¡","Ð¢","Ð£","Ð¤","Ð¥","Ð¦","Ð§","Ð¨","Ð©","Ðª","Ð«","Ð¬","Ð­","Ð®","Ð¯","Ð°","Ð±","Ð²","Ð³","Ð´","Ðµ","Ñ‘","Ð¶","Ð·","Ð¸","Ð¹","Ðº","Ð»","Ð¼","Ð½","Ð¾","Ð¿","Ñ€","Ñ","Ñ‚","Ñƒ","Ñ„","Ñ…","Ñ†","Ñ‡","Ñˆ","Ñ‰","ÑŠ","Ñ‹","ÑŒ","Ñ","ÑŽ","Ñ"];
@{char_tab{'WIN'}} = ["À","Á","Â","Ã","Ä","Å","¨","Æ","Ç","È","É","Ê","Ë","Ì","Í","Î","Ï","Ð","Ñ","Ò","Ó","Ô","Õ","Ö","×","Ø","Ù","Ú","Û","Ü","Ý","Þ","ß","à","á","â","ã","ä","å","¸","æ","ç","è","é","ê","ë","ì","í","î","ï","ð","ñ","ò","ó","ô","õ","ö","÷","ø","ù","ú","û","ü","ý","þ","ÿ"];
@{char_tab{'DOS'}} = ["€","","‚","ƒ","„","…","ð","†","‡","ˆ","‰","Š","‹","Œ","","Ž","","","‘","’","“","”","•","–","—","˜","™","š","›","œ","","ž","Ÿ"," ","¡","¢","£","¤","¥","ñ","¦","§","¨","©","ª","«","¬","­","®","¯","à","á","â","ã","ä","å","æ","ç","è","é","ê","ë","ì","í","î","ï"];
@{char_tab{'ISO'}} = ["°","±","²","³","´","µ","¡","¶","·","¸","¹","º","»","¼","½","¾","¿","À","Á","Â","Ã","Ä","Å","Æ","Ç","È","É","Ê","Ë","Ì","Í","Î","Ï","Ð","Ñ","Ò","Ó","Ô","Õ","ñ","Ö","×","Ø","Ù","Ú","Û","Ü","Ý","Þ","ß","à","á","â","ã","ä","å","æ","ç","è","é","ê","ë","ì","í","î","ï"];
@{char_tab{'KOI8'}} = ["á","â","÷","ç","ä","å","³","ö","ú","é","ê","ë","ì","í","î","ï","ð","ò","ó","ô","õ","æ","è","ã","þ","û","ý","ÿ","ù","ø","ü","à","ñ","Á","Â","×","Ç","Ä","Å","£","Ö","Ú","É","Ê","Ë","Ì","Í","Î","Ï","Ð","Ò","Ó","Ô","Õ","Æ","È","Ã","Þ","Û","Ý","ß","Ù","Ø","Ü","À","Ñ"];
@{char_tab{'MAC'}} = ["€","","‚","ƒ","„","…","Ý","†","‡","ˆ","‰","Š","‹","Œ","","Ž","","","‘","’","“","”","•","–","—","˜","™","š","›","œ","","ž","Ÿ","à","á","â","ã","ä","å","Þ","æ","ç","è","é","ê","ë","ì","í","î","ï","ð","ñ","ò","ó","ô","õ","ö","÷","ø","ù","ú","û","ü","ý","þ","ß"];

sub cyr_cstocs {
	my ($SOURCECHARSET, $DESTINATIONCHARSET, $INBUFFER) = @_;
        my $OUTBUFFER="";
        my @READCHAR=();
	$SOURCECHARSET= uc($SOURCECHARSET); 
        $SOURCECHARSET='KOI8' if ($SOURCECHARSET eq 'KOI') or ($SOURCECHARSET eq 'KOI8-R'); 
        $SOURCECHARSET='UTF8' if ($SOURCECHARSET eq 'UTF') or ($SOURCECHARSET eq 'UTF-8');
	$DESTINATIONCHARSET=uc($DESTINATIONCHARSET);
	$DESTINATIONCHARSET='KOI8' if ($DESTINATIONCHARSET eq 'KOI') or ($DESTINATIONCHARSET eq 'KOI8-R');
	$DESTINATIONCHARSET='UTF8' if ($DESTINATIONCHARSET eq 'UTF') or ($DESTINATIONCHARSET eq 'UTF-8');
	if ($SOURCECHARSET eq 'UTF8')
          {
           my $CHARCOUNT=0;
           $READCHAR[0]=bytes::substr($INBUFFER,0,1);
           while ( defined ($READCHAR[0]) )
            {
             # Cyrillic letters in UTF take two bytes.
             # Read two consequent bytes and check if they make a valid
	     # cyrillic letter
	     $CHARCOUNT++;
             $READCHAR[1]=bytes::substr($INBUFFER,$CHARCOUNT,1);
             if ((defined ($READCHAR[1]) 
              && ((bytes::ord($READCHAR[0])==208 && ((bytes::ord($READCHAR[1])>=144 && bytes::ord($READCHAR[1])<=191) || bytes::ord($READCHAR[1])==129)) 
                ||(bytes::ord($READCHAR[0])==209 && ((bytes::ord($READCHAR[1])>=128 && bytes::ord($READCHAR[1])<=143) || bytes::ord($READCHAR[1])==145)) )))
              {
               # The pair is a valid cyrillic UTF-8 letter - add corresponding
               # letter in the destination charset to the output buffer;
	       $READCHAR[0].=$READCHAR[1];
               for (my $CHARINDEX=0;$CHARINDEX<66;$CHARINDEX++)
                {
		 if (${char_tab{'UTF8'}}[$CHARINDEX] eq $READCHAR[0])
		  {
                   $OUTBUFFER.=${char_tab{$DESTINATIONCHARSET}}[$CHARINDEX];
		   last;
		  }
                }
	       $CHARCOUNT++;
	       $READCHAR[0]=bytes::substr($INBUFFER,$CHARCOUNT,1);
              }
             else
              {
               # The pair is not a valid cyrillic UTF-8 letter - copy the first
               # byte to the output buffer "as is" and make shift in the bytes;
               $OUTBUFFER.=$READCHAR[0];
               $READCHAR[0]=$READCHAR[1];
              }
	    }
          }
	 else
	  {
	   # Other encodings (KOI8-R,WIN,DOS,MAC,ISO) all use one byte for
	   # each letter.
           my $CHARCOUNT=0;
           $READCHAR[0]=bytes::substr($INBUFFER,0,1);
           while ( defined ($READCHAR[0]) )
            {
             for (my $CHARINDEX=0;$CHARINDEX<66;$CHARINDEX++)
              {
	       if ($READCHAR[0] eq ${char_tab{$SOURCECHARSET}}[$CHARINDEX])
	        {
		 $OUTBUFFER.=${char_tab{$DESTINATIONCHARSET}}[$CHARINDEX];
		 last;
		}
              }
	     $CHARCOUNT++;
             $READCHAR[0]=bytes::substr($INBUFFER,$CHARCOUNT,1);
	    }
	  }
	$OUTBUFFER;
}

my $WORK_DIR=".";
my $TOKENS_FILE=$WORK_DIR."/tokens.utf-8";
my $SPAMASSASSIN_RULES_DIR=".";
my $RULES_FILE_KOI8=$SPAMASSASSIN_RULES_DIR."/99_russian_koi8_re.cf";
my $RULES_FILE_WIN1251=$SPAMASSASSIN_RULES_DIR."/99_russian_win1251_re.cf";
my $RULES_FILE_UTF8=$SPAMASSASSIN_RULES_DIR."/99_russian_utf8_re.cf";
my $RULES_FILE_COMMON=$SPAMASSASSIN_RULES_DIR."/99_russian_common_re.cf";

# Define regexp patterns that will be used instead of ordinary letters to make
# the rules hit words with cyrillic and latin letters and digits mixed, and 
# also to make sure that pattern will cover both lower and upper cases of
# russian letters with any locale set.
# The cyrillic letters used as hash indices are in UTF-8 charset
my %SUBST_SET;
$SUBST_SET{'Ð°'}=["Ð°","Ð","a","A","\x40"];
$SUBST_SET{'Ð±'}=["Ð±","Ð‘","6"];
$SUBST_SET{'Ð²'}=["Ð²","Ð’","B","8"];
$SUBST_SET{'Ð³'}=["Ð³","Ð“"];
$SUBST_SET{'Ð´'}=["Ð´","Ð”"];
$SUBST_SET{'Ðµ'}=["Ðµ","Ð•","e","E"];
$SUBST_SET{'Ñ‘'}=["Ñ‘","Ð","Ðµ","Ð•","e","E"];
$SUBST_SET{'Ð¶'}=["Ð¶","Ð–"];
$SUBST_SET{'Ð·'}=["Ð·","Ð—","3"];
$SUBST_SET{'Ð¸'}=["Ð¸","Ð˜","u","U"];
$SUBST_SET{'Ð¹'}=["Ð¹","Ð™","Ð¸","Ð˜","u","U"];
$SUBST_SET{'Ðº'}=["Ðº","Ðš","k","K"];
$SUBST_SET{'Ð»'}=["Ð»","Ð›"];
$SUBST_SET{'Ð¼'}=["Ð¼","Ðœ","M"];
$SUBST_SET{'Ð½'}=["Ð½","Ð","H"];
$SUBST_SET{'Ð¾'}=["Ð¾","Ðž","o","O","0"];
$SUBST_SET{'Ð¿'}=["Ð¿","ÐŸ","n"];
$SUBST_SET{'Ñ€'}=["Ñ€","Ð ","p","P"];
$SUBST_SET{'Ñ'}=["Ñ","Ð¡","c","C"];
$SUBST_SET{'Ñ‚'}=["Ñ‚","Ð¢","T"];
$SUBST_SET{'Ñƒ'}=["Ñƒ","Ð£","y","Y"];
$SUBST_SET{'Ñ„'}=["Ñ„","Ð¤"];
$SUBST_SET{'Ñ…'}=["Ñ…","Ð¥","x","X"];
$SUBST_SET{'Ñ†'}=["Ñ†","Ð¦"];
$SUBST_SET{'Ñ‡'}=["Ñ‡","Ð§","4"];
$SUBST_SET{'Ñˆ'}=["Ñˆ","Ð¨","Ñ‰","Ð©","w","W"];
$SUBST_SET{'Ñ‰'}=["Ñˆ","Ð¨","Ñ‰","Ð©","w","W"];
$SUBST_SET{'ÑŠ'}=["ÑŠ","Ðª"];
$SUBST_SET{'Ñ‹'}=["Ñ‹","Ð«"]; # ,"b\|","Ð¬\|"
$SUBST_SET{'ÑŒ'}=["ÑŒ","Ð¬","b"];
$SUBST_SET{'Ñ'}=["Ñ","Ð­"];
$SUBST_SET{'ÑŽ'}=["ÑŽ","Ð®"];
$SUBST_SET{'Ñ'}=["Ñ","Ð¯"];
$SUBST_SET_SPECIAL{'<#DIGIT#>'}=["[[:digit:]]","Ð¾","Ðž","o","O","I","l","Ð·","Ð—","Ñ‡","Ð§","Ð±","Ð²","Ð’"];
$SUBST_SET_SPECIAL{'<#0#>'}=["0","Ð¾","Ðž","o","O"];
$SUBST_SET_SPECIAL{'<#1#>'}=["1","I","l"];
$SUBST_SET_SPECIAL{'<#2#>'}=["2"];
$SUBST_SET_SPECIAL{'<#3#>'}=["3","Ð·","Ð—"];
$SUBST_SET_SPECIAL{'<#4#>'}=["4","Ñ‡","Ð§"];
$SUBST_SET_SPECIAL{'<#5#>'}=["5"];
$SUBST_SET_SPECIAL{'<#6#>'}=["6","Ð±"];
$SUBST_SET_SPECIAL{'<#7#>'}=["7"];
$SUBST_SET_SPECIAL{'<#8#>'}=["8","Ð²","Ð’","B"];
$SUBST_SET_SPECIAL{'<#9#>'}=["9"];

#********************************

# Now create hash of strings to replace single letters with regexp
# patterns
my %CHAR_SUBST;
foreach my $SUBST_EXPR ( keys(%SUBST_SET) )
 {
  $CHAR_SUBST_UTF8{$SUBST_EXPR}="(";
  $CHAR_SUBST_KOI8{$SUBST_EXPR}="(";
  $CHAR_SUBST_WIN1251{$SUBST_EXPR}="(";
  foreach my $SUBST_EXPR1 (@{$SUBST_SET{$SUBST_EXPR}})
   {
    if ( ord(bytes::substr($SUBST_EXPR1,0,1))<128 )
     {
      $CHAR_SUBST_UTF8{$SUBST_EXPR}.=($SUBST_EXPR1."|");
      $CHAR_SUBST_KOI8{$SUBST_EXPR}.=($SUBST_EXPR1."|");
      $CHAR_SUBST_WIN1251{$SUBST_EXPR}.=($SUBST_EXPR1."|");
     }
    else
     {
      $CHAR_SUBST_UTF8{$SUBST_EXPR}.="(\\x".unpack('H2',bytes::substr($SUBST_EXPR1,0,1))."\\x".unpack('H2',bytes::substr($SUBST_EXPR1,1,1)).")";
      $CHAR_SUBST_UTF8{$SUBST_EXPR}.="|";
      $SUBST_EXPR2=cyr_cstocs ("UTF-8", "KOI8", $SUBST_EXPR1);
      $CHAR_SUBST_KOI8{$SUBST_EXPR}.="\\x".unpack('H2',$SUBST_EXPR2)."|";
      $SUBST_EXPR2=cyr_cstocs ("UTF-8", "WIN", $SUBST_EXPR1);
      $CHAR_SUBST_WIN1251{$SUBST_EXPR}.="\\x".unpack('H2',$SUBST_EXPR2)."|";
     }
   }
  $CHAR_SUBST_UTF8{$SUBST_EXPR}=~s/\|$/\)\(\[\[\:blank\:\]\[\:punct\:\]\]\?\)/;
  $CHAR_SUBST_KOI8{$SUBST_EXPR}=~s/\|$/\)\(\[\[\:blank\:\]\[\:punct\:\]\]\?\)/;
  $CHAR_SUBST_WIN1251{$SUBST_EXPR}=~s/\|$/\)\(\[\[\:blank\:\]\[\:punct\:\]\]\?\)/;
 }

# Now create hash of strings to replace spectal pseudo-patterns with regexp
# patterns

foreach my $SUBST_EXPR ( keys(%SUBST_SET_SPECIAL) )
 {
  $CHAR_SUBST_SPECIAL_UTF8{$SUBST_EXPR}="((";
  $CHAR_SUBST_SPECIAL_KOI8{$SUBST_EXPR}="((";
  $CHAR_SUBST_SPECIAL_WIN1251{$SUBST_EXPR}="((";
  foreach my $SUBST_EXPR1 (@{$SUBST_SET_SPECIAL{$SUBST_EXPR}})
   {
    if ( ord(bytes::substr($SUBST_EXPR1,0,1))<128 )
     {
      $CHAR_SUBST_SPECIAL_UTF8{$SUBST_EXPR}.=($SUBST_EXPR1."|");
      $CHAR_SUBST_SPECIAL_KOI8{$SUBST_EXPR}.=($SUBST_EXPR1."|");
      $CHAR_SUBST_SPECIAL_WIN1251{$SUBST_EXPR}.=($SUBST_EXPR1."|");
     }
    else
     {
      $CHAR_SUBST_SPECIAL_UTF8{$SUBST_EXPR}.="(\\x".unpack('H2',bytes::substr($SUBST_EXPR1,0,1))."\\x".unpack('H2',bytes::substr($SUBST_EXPR1,1,1)).")";
      $CHAR_SUBST_SPECIAL_UTF8{$SUBST_EXPR}.="|";
      $SUBST_EXPR2=cyr_cstocs ("UTF-8", "KOI8", $SUBST_EXPR1);
      $CHAR_SUBST_SPECIAL_KOI8{$SUBST_EXPR}.="\\x".unpack('H2',$SUBST_EXPR2)."|";
      $SUBST_EXPR2=cyr_cstocs ("UTF-8", "WIN", $SUBST_EXPR1);
      $CHAR_SUBST_SPECIAL_WIN1251{$SUBST_EXPR}.="\\x".unpack('H2',$SUBST_EXPR2)."|";
     }
   }
  $CHAR_SUBST_SPECIAL_UTF8{$SUBST_EXPR}=~s/\|$/\)\(\[\[\:blank\:\]\[\:punct\:\]\]\*\)\)/;
  $CHAR_SUBST_SPECIAL_KOI8{$SUBST_EXPR}=~s/\|$/\)\(\[\[\:blank\:\]\[\:punct\:\]\]\*\)\)/;
  $CHAR_SUBST_SPECIAL_WIN1251{$SUBST_EXPR}=~s/\|$/\)\(\[\[\:blank\:\]\[\:punct\:\]\]\*\)\)/;
#  print $SUBST_EXPR.":\n" ;
#  print "UTF8: ".$CHAR_SUBST_SPECIAL_UTF8{$SUBST_EXPR}."\n";
#  print "KOI8: ".$CHAR_SUBST_SPECIAL_KOI8{$SUBST_EXPR}."\n";
#  print "WIN1251: ".$CHAR_SUBST_SPECIAL_WIN1251{$SUBST_EXPR}."\n";
 } 

# Now open the tokens list and build rules based on them
open(TOKENS,'<',$TOKENS_FILE) || die "Could not open file ".$TOKENS_FILE."\n";
open(RULES_KOI8,'>',$RULES_FILE_KOI8) || die "Could not open file ".$RULES_FILE_KOI8."\n";
open(RULES_WIN1251,'>',$RULES_FILE_WIN1251) || die "Could not open file ".$RULES_FILE_WIN1251."\n";
open(RULES_UTF8,'>',$RULES_FILE_UTF8) || die "Could not open file ".$RULES_FILE_UTF8."\n";
open(RULES_COMMON,'>',$RULES_FILE_COMMON) || die "Could not open file ".$RULES_FILE_COMMON."\n";
while ( my $TOKENS_LINE = <TOKENS> )
 {
  if (( $TOKENS_LINE !~ /^#.*/ ) && ( $TOKENS_LINE !~ /^(\s)*(\n)?$/ ))
   {
    # The line is neither a comment nor empty - process it
    chomp $TOKENS_LINE;
    @PARTS=split(/\s+/,$TOKENS_LINE); # Split the line into fields and check
                                      # if it is a tokens line (which consists
				      # of the rule name starting with "RU_"
				      # and the tokens string itself), a meta-rule
				      # definition (which starts with "meta"
				      # keyword), or a score definition (which
				      # starts with "score" keyword)
    if ( scalar(@PARTS) != 2 )
     {
      # The tokens line must consist of rule name, folowed by whitespace, and
      # the tokens string itself. There must be no whitespaces within the
      # tokens string (only "\s" or [[:blank:]] regexp constructs)
      # If a line is not a valid tokens line - it can be a score definition,
      # a meta-rule definition, or a non-russian rule definition. In these
      # cases it will be copied to the rules with charset name added where
      # necessary. Otherwise it will be skipped with warning.
      # 
      if ( ( $PARTS[0] eq "score" ) && ( $PARTS[2]=~/(\-)?[[:digit:]]+(\.)?[[:digit:]]*/ ) )
       {
        if ($PARTS[1]=~/^RU_.*/)
	 {
	  print RULES_KOI8 "score ".$PARTS[1]."_KOI8 ".$PARTS[2]."\n";
	  print RULES_WIN1251 "score ".$PARTS[1]."_WIN1251 ".$PARTS[2]."\n";
	  print RULES_UTF8 "score ".$PARTS[1]."_UTF8 ".$PARTS[2]."\n";
         }
	else
	 {
	  print RULES_COMMON "score ".$PARTS[1]." ".$PARTS[2]."\n";
	 }
       }
      elsif ( $PARTS[0] eq "meta" )
       {
        if ( $PARTS[1]=~/^(__)?RU_.*/ )
	 {
	  $RULES_LINE_KOI8="meta ".$PARTS[1]."_KOI8 ";
	  $RULES_LINE_WIN1251="meta ".$PARTS[1]."_WIN1251 ";
	  $RULES_LINE_UTF8="meta ".$PARTS[1]."_UTF8 ";
          for (my $CHARINDEX=2;$CHARINDEX<scalar(@PARTS);$CHARINDEX++)
	   {
	    if($PARTS[$CHARINDEX]=~/^(__)?RU_.*/)
	     {
	      $RULES_LINE_KOI8.=$PARTS[$CHARINDEX]."_KOI8 ";
	      $RULES_LINE_WIN1251.=$PARTS[$CHARINDEX]."_WIN1251 ";
	      $RULES_LINE_UTF8.=$PARTS[$CHARINDEX]."_UTF8 ";
	     }
	    else
	     {
	      $RULES_LINE_KOI8.=$PARTS[$CHARINDEX]." ";
	      $RULES_LINE_WIN1251.=$PARTS[$CHARINDEX]." ";
	      $RULES_LINE_UTF8.=$PARTS[$CHARINDEX]." ";
	     }
	   }
	  print RULES_KOI8 $RULES_LINE_KOI8."\n";
	  print RULES_WIN1251 $RULES_LINE_WIN1251."\n";
	  print RULES_UTF8 $RULES_LINE_UTF8."\n";
	 }
	elsif ( $TOKENS_LINE != /.*([[:blank:]]|(__))RU.*/ )
	 {
	  print RULES_COMMON $TOKENS_LINE."\n";
	 }
	else
	 {
	  print "Error in line \"".$TOKENS_LINE."\" - russian sub-rule in non-russian meta-rule\n";
	 }
       }
      elsif ($PARTS[0] =~ /(body)|(rawbody)/)
      #(redirector_pattern)|(header)|(uri)|(full)
       {
        print RULES_COMMON $TOKENS_LINE."\n";
       }
      else
       {
        print "Error in line \"".$TOKENS_LINE."\"\n";
       }
     }
    else
     {
      # This is a valid tokens line - process it.
      # First, find pre-defined patterns (such as "<#DIGIT#>") and replace
      # them with appropriate regexps
      # Walk through the tokens line, find cyrillic letters and replace them
      # with appropriate regexp
      my $CHARCOUNT=0;
      my $RULES_LINE_UTF8="";
      my $RULES_LINE_KOI8="";
      my $RULES_LINE_WIN1251="";
      my @READCHAR=();
      $READCHAR[0]=bytes::substr($PARTS[1],0,1);
      while ( defined ($READCHAR[0]) )
       {
        # Cyrillic letters in UTF take two bytes.
        # Read two consequent bytes and check if they make a valid
        # cyrillic letter
	$CHARCOUNT++;
        $READCHAR[1]=bytes::substr($PARTS[1],$CHARCOUNT,1);
        if ((defined ($READCHAR[1]) 
          &&((bytes::ord($READCHAR[0])==208 && ((bytes::ord($READCHAR[1])>=144 && bytes::ord($READCHAR[1])<=191) || bytes::ord($READCHAR[1])==129)) 
           ||(bytes::ord($READCHAR[0])==209 && ((bytes::ord($READCHAR[1])>=128 && bytes::ord($READCHAR[1])<=143) || bytes::ord($READCHAR[1])==145)) )))
         {
          # The pair is a valid cyrillic UTF-8 letter - replace it with proper
	  # regexp. Only run over lower-case part of charset table
	  $READCHAR[0].=$READCHAR[1];
          for (my $CHARINDEX=33;$CHARINDEX<66;$CHARINDEX++)
	   {
	    if ($READCHAR[0] eq ${char_tab{'UTF8'}}[$CHARINDEX])
	     {
	      $RULES_LINE_UTF8.=$CHAR_SUBST_UTF8{$READCHAR[0]};
	      $RULES_LINE_KOI8.=$CHAR_SUBST_KOI8{$READCHAR[0]};
              $RULES_LINE_WIN1251.=$CHAR_SUBST_WIN1251{$READCHAR[0]};
	      last;
	     }
	   }
	  $CHARCOUNT++;
	  $READCHAR[0]=bytes::substr($PARTS[1],$CHARCOUNT,1);
         }
        else
         {
          # The pair is not a cyrillic letter - copy the first byte "as is"
	  # and shift second byte to first
	  $RULES_LINE_UTF8.=$READCHAR[0];
	  $RULES_LINE_KOI8.=$READCHAR[0];
	  $RULES_LINE_WIN1251.=$READCHAR[0];
	  $READCHAR[0]=$READCHAR[1];
         }
       } # while ( defined ($READCHAR[0]) )
      # Now scan RULES_LINEs to find encoding-independent pseudo-patterns
      # (such as <#DIGIT#>) to replace them with regexps
      foreach my $SUBST_EXPR ( keys(%SUBST_SET_SPECIAL) )
       {
        $RULES_LINE_UTF8=~s/$SUBST_EXPR/$CHAR_SUBST_SPECIAL_UTF8{$SUBST_EXPR}/g;
        $RULES_LINE_KOI8=~s/$SUBST_EXPR/$CHAR_SUBST_SPECIAL_KOI8{$SUBST_EXPR}/g;
        $RULES_LINE_WIN1251=~s/$SUBST_EXPR/$CHAR_SUBST_SPECIAL_WIN1251{$SUBST_EXPR}/g;
       }
      # Print tokens in various encodings, so that one can read them and decide
      # if he/she needs this rule
      print RULES_KOI8 "# -------------------\n";
      print RULES_KOI8 "# KOI8-R: \"".cyr_cstocs ("UTF8", "KOI8", $PARTS[1])."\" \n";
      print RULES_KOI8 "# Win1251: \"".cyr_cstocs ("UTF8", "WIN", $PARTS[1])."\" \n";
      print RULES_KOI8 "# UTF8: \"".$PARTS[1]."\" \n";
      print RULES_WIN1251 "# -------------------\n";
      print RULES_WIN1251 "# KOI8-R: \"".cyr_cstocs ("UTF8", "KOI8", $PARTS[1])."\" \n";
      print RULES_WIN1251 "# Win1251: \"".cyr_cstocs ("UTF8", "WIN", $PARTS[1])."\" \n";
      print RULES_WIN1251 "# UTF8: \"".$PARTS[1]."\" \n";
      print RULES_UTF8 "# -------------------\n";
      print RULES_UTF8 "# KOI8-R: \"".cyr_cstocs ("UTF8", "KOI8", $PARTS[1])."\" \n";
      print RULES_UTF8 "# Win1251: \"".cyr_cstocs ("UTF8", "WIN", $PARTS[1])."\" \n";
      print RULES_UTF8 "# UTF8: \"".$PARTS[1]."\" \n";
      print RULES_KOI8 "body ".$PARTS[0]."_KOI8 /".$RULES_LINE_KOI8."/ms\n";
      print RULES_WIN1251 "body ".$PARTS[0]."_WIN1251 /".$RULES_LINE_WIN1251."/ms\n";
      print RULES_UTF8 "body ".$PARTS[0]."_UTF8 /".$RULES_LINE_UTF8."/ms\n";
     } # if ( scalar(@PARTS) != 2 )
   } # if this is not a comment
 } # loop over lines in tokens list


close TOKENS;
close RULES_KOI8;
close RULES_WIN1251;
close RULES_UTF8;
close RULES_COMMON;
