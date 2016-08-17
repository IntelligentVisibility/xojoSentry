#tag Class
Protected Class XojoSentry
	#tag Method, Flags = &h0
		Sub constructor(DSN as Text)
		  ParseDSN(DSN)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GenerateJSON(mException as RuntimeException, currentFunction As String , extra as string="", description as string) As JSONItem
		  
		  // build the stack frame array
		  dim stack as new JSONItem
		  dim cstack() as xojo.Core.StackFrame=mException.CallStack
		  for i as integer=cstack.Ubound downto 0
		    dim frame as xojo.Core.StackFrame=cstack(i)
		    dim jframe as new JSONItem
		    dim fname as String=frame.Name
		    jframe.Value("function")=fname
		    jframe.Value("filename")=str(frame.Address)
		    jframe.Value("module")="-"
		    stack.Append jframe
		  next
		  dim stacktrace as new JSONItem
		  stacktrace.Value("frames")=stack
		  
		  // add general info
		  dim timestamp as string=d.Year.ToText+"-"+d.Month.ToText+"-"+d.Day.ToText+"T"+d.Hour.ToText+":"+d.Minute.ToText+":"+d.Minute.ToText
		  dim j as new JSONItem
		  j.Value("event_id")=GenerateUUID
		  j.Value("message")=currentFunction+chr(10)+description
		  j.Value("stacktrace")=stacktrace
		  j.Value("timestamp")=timestamp
		  j.Value("platform")="other"
		  j.Value("release")=str(app.MajorVersion)+"."+str(app.MinorVersion)+"."+str(app.BugVersion)+"."+str(app.StageCode)
		  dim tags As new JSONItem
		  tags.Value("extra")=extra
		  tags.Value("culprit")=currentFunction
		  j.Value("tags")=tags
		  
		  //add os version info
		  dim contexts as new JSONItem
		  dim osinfo as new JSONItem
		  dim sh as new Shell
		  #if TargetLinux
		    sh.Execute("lsb_release", "-is")
		    osinfo.Value("name")=sh.Result
		    sh.Execute("lsb_release", "-rs")
		    osinfo.Value("version")=sh.Result
		  #elseif TargetMacOS
		    osinfo.Value("name")="MacOS"
		    sh.Execute("sw_vers -productVersion")
		    osinfo.Value("version")=sh.Result
		  #Elseif TargetWindows
		    osinfo.Value("name")="Windows"
		    //hoops to get win os version
		    declare Function GetFileVersionInfoA lib "Api-ms-win-core-version-l1-1-0.dll" (filename as cstring,handle as uint32,len as uint32,p as ptr) as Boolean
		    declare Function GetFileVersionInfoSizeA lib "Api-ms-win-core-version-l1-1-0.dll" (filename as cstring,byref o as uint32) as uint32
		    declare Function VerQueryValueA lib "Api-ms-win-core-version-l1-1-0.dll" (block as ptr,name  as cstring,byref buffer as ptr,byref sze as uint32) as Boolean
		    dim o as uint32
		    dim s as uint32=GetFileVersionInfoSizeA("user32.dll",o)
		    dim v as new MemoryBlock(s)
		    dim r as ptr
		    v.UInt32Value(0)=s
		    if GetFileVersionInfoA("User32.dll",0,s,v) then
		      if VerQueryValueA(v,"\",r,o) then
		        dim res as MemoryBlock=r
		        osinfo.Value("version")=str(res.UInt16Value(18))+"."+str(res.UInt16Value(16))+" "+str(res.UInt16Value(22))+"."+str(res.UInt16Value(20))
		      end if
		    end if
		  #Endif
		  
		  contexts.Value("os")=osinfo
		  
		  //info about the version of Xojo
		  dim runtime as new JSONItem
		  runtime.Value("name")="Xojo"
		  runtime.Value("version")=XojoVersionString
		  contexts.Value("runtime")=runtime
		  j.Value("contexts")=contexts
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
		  //break out the DSN into the needed parts
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
		Function SubmitException(mException as RuntimeException,currentFunction as String, extra as String, description as string="") As JSONItem
		  //We use  HTTPS
		  dim sock as new HTTPSecureSocket
		  sock.Address=uri
		  
		  //Grab the current time in GMT
		  Dim GMTZone As New xojo.core.TimeZone("GMT")
		  d=new xojo.core.date(xojo.Core.Date.now.SecondsFrom1970,GMTZone)
		  
		  //Build the header to submit
		  dim header as String
		  header="?sentry_version=7&sentry_client=Xojo-Sentry/"+Version+"&" + _
		  "sentry_timestamp="+Format(d.SecondsFrom1970,"#######")+"&" + _
		  "sentry_key="+PublicKey+"&" + _
		  "sentry_secret="+SecretKey
		  
		  sock.SetRequestHeader("User-Agent","Xojo-Sentry/"+Version)
		  
		  //Create the JSONItem that contains all the relevalt data
		  dim content as JSONItem=GenerateJSON(mException,currentFunction,extra,description)
		  sock.SetRequestContent(content.ToString,"application/json")
		  
		  //send off the report
		  dim res as string = sock.SendRequest("POST",uri+"/api/"+ProjectID+"/store/"+header,100)
		  if sock.ErrorCode=0 then
		    Return new JSONItem(res) //contains a report id
		  else
		    Return content //Something failed.. we could save this for submission on next run
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
