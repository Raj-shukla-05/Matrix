"""20 labelled sample messages. These were written for the demo. Replace or extend them with
real messages from your own WhatsApp, Telegram, LinkedIn and email before the pitch, then
re-run evaluate.py so the accuracy number on your slide is measured on real data."""

SAMPLES = [
    # ------------------------------------------------------------ scams
    {"title": "Data entry job with registration fee", "label": "scam", "text":
     "URGENT HIRING!!! Work from home data entry job. Earn Rs. 5000 per day. No experience needed. "
     "Pay Rs 1500 registration fee (refundable) to start. Contact HR on WhatsApp 9876543210. "
     "Join today, limited seats!"},
    {"title": "Amazon rate products task", "label": "scam", "text":
     "Amazon is hiring part time work from home. Rate products and earn 3000 daily. "
     "Send your Aadhaar and PAN to confirm. Apply: https://bit.ly/amz-jobs2 "
     "Message on Telegram @amazon_hr_official"},
    {"title": "Hinglish typing job", "label": "scam", "text":
     "Ghar baithe paise kamao! Typing job, bina interview ke direct joining. "
     "Rs 800 security deposit jama karna hoga. Jaldi WhatsApp karein 9123456780. Seat limited hai."},
    {"title": "Fake Infosys offer letter", "label": "scam", "text":
     "Congratulations! You are selected for Software Engineer at Infosys. No interview required. "
     "Your offer letter will be issued after you pay Rs 4,999 as processing fee. "
     "Email hr.infosys.careers@gmail.com. Package 12 LPA."},
    {"title": "YouTube like task group", "label": "scam", "text":
     "Like YouTube videos and earn Rs 50 per video. Task based part time job. "
     "Earn up to 30k weekly. Join our Telegram group t.me/earnquick99. 100% guaranteed payment."},
    {"title": "OTP request in a TCS interview mail", "label": "scam", "text":
     "Dear candidate, your TCS interview is scheduled. To verify your profile share the OTP received "
     "on your mobile and your bank account number. Contact tcs.recruitment2026@yahoo.com immediately."},
    {"title": "Gulf job with agent fee", "label": "scam", "text":
     "Gulf jobs available! Salary 1 lakh per month, no experience, free visa. "
     "Pay 25000 agent fee for visa processing. WhatsApp +91 98765 43210."},
    {"title": "Earn 40k from home link", "label": "scam", "text":
     "Work from home. Earn 40,000 per month sitting at home. Just 2 hours daily. "
     "Apply now: http://quick-earn-jobs.xyz/apply. Hurry, last date today!"},
    {"title": "Soft scam: laptop kit purchase", "label": "scam", "text":
     "Hi, I am Priya from Global Talent HR. We have a work from home opportunity for freshers, salary 25000 "
     "monthly. Interested candidates share your resume on WhatsApp 9000000000. Selected candidates need to "
     "buy the company laptop kit of Rs 3000, it will be reimbursed."},
    {"title": "Fake UP government clerk vacancy", "label": "scam", "text":
     "Dear Student, Govt of UP is hiring 5000 clerks under Yojana. Registration fee Rs 300 only. "
     "Apply at http://upgovt-jobs.online/form. Last date tomorrow. Aadhaar required."},
    # ------------------------------------------------------------ genuine
    {"title": "Infosys campus hiring mail", "label": "genuine", "text":
     "Hi, Rahul from Infosys Talent Acquisition. We are hiring Systems Engineers (2026 batch). CTC 3.6 LPA. "
     "Process: online assessment, technical interview, HR interview. Apply only at "
     "https://www.infosys.com/careers. We never ask candidates for any money. Contact: rahul.s@infosys.com"},
    {"title": "Wipro hiring notification", "label": "genuine", "text":
     "Wipro Elite hiring notification: BCA and B.Sc 2026 batch eligible. Apply at careers.wipro.com. "
     "Shortlisted candidates will get an assessment link from no-reply@wipro.com. "
     "Wipro does not charge any fee at any stage."},
    {"title": "Startup intern post with WhatsApp for queries", "label": "genuine", "text":
     "Hello, we are Brightpath Analytics Pvt Ltd, Lucknow. Hiring Python Intern, stipend Rs 10,000 per month, "
     "3 month duration. Interview on Google Meet next Monday 11 AM. Send resume to "
     "careers@brightpathanalytics.in. Website: https://brightpathanalytics.in. "
     "For queries WhatsApp 9455512345."},
    {"title": "College placement cell notice", "label": "genuine", "text":
     "Placement cell notice: Capgemini on-campus drive on 5 Nov in Block A seminar hall. "
     "Eligible: B.Tech CS/IT 2026, 60 percent and above. Carry resume and college ID. "
     "Aptitude test followed by technical and HR interview. Register on the placement portal before 2 Nov."},
    {"title": "LinkedIn analyst post", "label": "genuine", "text":
     "Hiring: Junior Data Analyst at Zenith Retail Solutions, Noida. Experience 1 to 2 years, SQL and Excel "
     "required. Salary 4 to 6 LPA. Apply via LinkedIn Easy Apply: https://www.linkedin.com/jobs/view/1234567890. "
     "Shortlisted candidates will be called for two interview rounds."},
    {"title": "Part time content writer", "label": "genuine", "text":
     "Our company Nexora Technologies Pvt Ltd needs a part time content writer, 20 hours per week, "
     "Rs 12,000 per month. Please send 2 writing samples to hr@nexoratech.in. Interview will be scheduled "
     "after sample review. No fee is charged at any stage."},
    {"title": "UPSSSC fake-site warning", "label": "genuine", "text":
     "UPSSSC has released the PET notification. Candidates can apply online only on the official site "
     "upsssc.gov.in. Please beware of fake websites and agents who promise jobs for money."},
    {"title": "Internship offer email", "label": "genuine", "text":
     "Congratulations Aman, you have been selected for a 2 month Web Development internship at Cloudnest "
     "Systems. Stipend Rs 8,000 per month. Joining on 3 Nov, 10 AM at our Lucknow office, Gomti Nagar. "
     "Please carry your original ID and resume. Offer letter is attached to this email from "
     "hr@cloudnestsystems.com. Regards, HR Team"},
    {"title": "TPO campus drive notice", "label": "genuine", "text":
     "Dear students, Mahindra campus drive on 8 Nov. Contact the Training and Placement Officer, "
     "Prof. Sharma, in room 204. Bring 2 resume copies. Free registration at the TPO office. "
     "Dress code is formal."},
    {"title": "Employee referral from a friend", "label": "genuine", "text":
     "Hi, my company HCLTech is hiring freshers for the Graduate Engineer Trainee role. Send your resume to me "
     "and I will refer you in the internal portal. Salary around 4 LPA. Selection will be through aptitude, "
     "technical and HR interview. Check the official site hcltech.com/careers for details."},
]
