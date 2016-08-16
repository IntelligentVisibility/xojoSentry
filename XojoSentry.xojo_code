#tag Class
Protected Class XojoSentry
	#tag Method, Flags = &h0
		Sub constructor(DSN as Text)
		  ParseDSN(DSN)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GenerateJSON(mException as RuntimeException, currentFunction As String , extra as string="") As JSONItem
		  dim stack() As xojo.Core.StackFrame=mException.CallStack
		  dim stackText as String=currentFunction+mException.Reason+chr(10)
		  
		  for Each frame as xojo.Core.StackFrame in stack
		    stackText=stackText+frame.Name+chr(10)
		  next
		  
		  dim timestamp as string=d.Year.ToText+"-"+d.Month.ToText+"-"+d.Day.ToText+"T"+d.Hour.ToText+":"+d.Minute.ToText+":"+d.Minute.ToText
		  dim j as new JSONItem
		  j.Value("event_id")=GenerateUUID
		  j.Value("message")=stacktext
		  j.Value("timestamp")=timestamp
		  j.Value("platform")="other"
		  j.Value("release")=str(app.MajorVersion)+"."+str(app.MinorVersion)+"."+str(app.BugVersion)+"."+str(app.StageCode)
		  dim tags As new JSONItem
		  tags.Value("extra")=extra
		  tags.Value("culprit")=currentFunction
		  j.Value("tags")=tags
		  
		  Return j
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GenerateUUID() As String
		  //From https://forum.xojo.com/18029-native-uuid-generation/0
		  'By Kem Tekinay
		  
		  
		  // From http://www.cryptosys.net/pki/uuid-rfc4122.html
		  //
		  // Generate 16 random bytes (=128 bits)
		  // Adjust certain bits according to RFC 4122 section 4.4 as follows:
		  // set the four most significant bits of the 7th byte to 0100'B, so the high nibble is '4'
		  // set the two most significant bits of the 9th byte to 10'B, so the high nibble will be one of '8', '9', 'A', or 'B'.
		  // Convert the adjusted bytes to 32 hexadecimal digits
		  // Add four hyphen '-' characters to obtain blocks of 8, 4, 4, 4 and 12 hex digits
		  // Output the resulting 36-character string "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
		  
		  dim randomBytes as MemoryBlock = Crypto.GenerateRandomBytes(16)
		  randomBytes.LittleEndian = false
		  
		  //
		  // Adjust seventh byte
		  //
		  dim value as byte = randomBytes.Byte(6)
		  value = value and &b00001111 // Turn off the first four bits
		  value = value or &b01000000 // Turn on the second bit
		  randomBytes.Byte(6) = value
		  
		  //
		  // Adjust ninth byte
		  //
		  value = randomBytes.Byte(8)
		  value = value and &b00111111 // Turn off the first two bits
		  value = value or &b10000000 // Turn on the first bit
		  randomBytes.Byte(8) = value
		  
		  
		  dim result as string = EncodeHex(randomBytes)
		  result = result.LeftB(8) + result.MidB(9, 4) + result.MidB(13, 4) + result.MidB(17, 4) + result.RightB(12)
		  
		  return result
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ParseDSN(dsn as text)
		  dim r as new RegEx
		  r.SearchPattern="(.*):\/\/(.*)\:(.*)\@(.*)\/(.*)"
		  
		  dim m as RegExMatch=r.Search(dsn)
		  
		  URI=m.SubExpressionString(1).ToText+"://"+m.SubExpressionString(4).ToText
		  PublicKey=m.SubExpressionString(2).ToText
		  SecretKey=m.SubExpressionString(3).ToText
		  ProjectID=m.SubExpressionString(5).ToText
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function SubmitException(mException as RuntimeException,currentFunction as String="", extra as String) As JSONItem
		  dim sock as new HTTPSecureSocket
		  sock.Address=uri
		  Dim GMTZone As New xojo.core.TimeZone("GMT")
		  d=new xojo.core.date(xojo.Core.Date.now.SecondsFrom1970,GMTZone)
		  
		  dim header as String
		  header="?sentry_version=7&sentry_client=Xojo-Sentry/"+Version+"&" + _
		  "sentry_timestamp="+Format(d.SecondsFrom1970,"#######")+"&" + _
		  "sentry_key="+PublicKey+"&" + _
		  "sentry_secret="+SecretKey
		  
		  sock.SetRequestHeader("User-Agent","Xojo-Sentry/"+Version)
		  
		  dim content as JSONItem=GenerateJSON(mException,currentFunction,extra)
		  sock.SetRequestContent(content.ToString,"application/json")
		  
		  dim res as string = sock.SendRequest("POST",uri+"/api/"+ProjectID+"/store/"+header,100)
		  if sock.ErrorCode=0 then
		    Return new JSONItem(res)
		  else
		    Return content
		  end if
		End Function
	#tag EndMethod


	#tag Property, Flags = &h0
		d As xojo.Core.Date
	#tag EndProperty

	#tag Property, Flags = &h21
		Private ProjectID As Text
	#tag EndProperty

	#tag Property, Flags = &h21
		Private PublicKey As text
	#tag EndProperty

	#tag Property, Flags = &h21
		Private SecretKey As Text
	#tag EndProperty

	#tag Property, Flags = &h21
		Private URI As Text
	#tag EndProperty


	#tag Constant, Name = Version, Type = String, Dynamic = False, Default = \"0.1", Scope = Private
	#tag EndConstant


	#tag ViewBehavior
		#tag ViewProperty
			Name="Index"
			Visible=true
			Group="ID"
			InitialValue="-2147483648"
			Type="Integer"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Left"
			Visible=true
			Group="Position"
			InitialValue="0"
			Type="Integer"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Name"
			Visible=true
			Group="ID"
			Type="String"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Super"
			Visible=true
			Group="ID"
			Type="String"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Top"
			Visible=true
			Group="Position"
			InitialValue="0"
			Type="Integer"
		#tag EndViewProperty
	#tag EndViewBehavior
End Class
#tag EndClass
