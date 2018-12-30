using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;

namespace mormotClient
{
    public class SampleRecord
    {
        public int ID { get; set; }
        public Int64 Time { get; set; }
        public string Name { get; set; }
        public string Question { get; set; }
    }

    public partial class MainPage : ContentPage
    {
        public MainPage()
        {
            InitializeComponent();           
        }

        async void Mormot_Clicked(object sender, EventArgs e)
        {
            var client = new MormotClient();
            await client.AuthorizeUser("http://localhost:8080", "root", "User", "synopse");


            HttpResponseMessage response = await client.GetAsync("root/SampleRecord/1");
            if (response != null)
            {
                var jsonString = await response.Content.ReadAsStringAsync();
                var test = JsonConvert.DeserializeObject<SampleRecord>(jsonString);
                lbQuestion.Text = test.Name +": "+ test.Question;
            }
        }
    }
}
