
// const express = require("express");
// // const app = express();
// const client = require("./db.js")
// const db = client.db()


// ======================
// sidenav functions
// ======================


function openNotificationNav() {
    document.getElementById("mySidenavNotification").style.width = "90%";
}
function closeNotificationNav() {
    document.getElementById("mySidenavNotification").style.width = "0";
}

function openResupplyEquipmentNav() {
    document.getElementById("mySidenavResupplyEquipment").style.width = "90%";
}
function closeResupplyEquipmentNav() {
    document.getElementById("mySidenavResupplyEquipment").style.width = "0";
}

function openSchedulingNav() {
    document.getElementById("mySidenavScheduling").style.width = "90%";
}
function closeSchedulingNav() {
    document.getElementById("mySidenavScheduling").style.width = "0";
}

function openSafetySignageNav() {
    document.getElementById("mySidenavSafetySignage").style.width = "90%";
}
function closeSafetySignageNav() {
    document.getElementById("mySidenavSafetySignage").style.width = "0";
}


function findEquipment() {

    document.getElementById('renderDB').innerHTML = window.results
    console.log("findEquipment function clicked")
};

function showList() {
   
    console.log("clicked showList button getting data from database")
    var result = [];
    for (var i = 0; i < 5; i++) {
        result.push(i);
    }
    // document.getElementById('render').innerHTML = result.join('<br>');
    document.getElementById('render1').innerHTML = "Backboard... Low Supply  at Top of Chair lift";
    document.getElementById('render2').innerHTML = "Arm splint.. Low Supply at Top of Chair lift";
    document.getElementById('render3').innerHTML = "Leg splint.. Low Supply at Top of Chair lift";
    document.getElementById('render4').innerHTML = "Neck brace c-collar.. Low Supply at Top of Chair lift";
    document.getElementById('render5').innerHTML = "Toboggan Sled for Injured..Low Supply at Top of Chair lift";
    document.getElementById('render7').innerHTML = "Water, snow drill, signage, rope, for patrol hut...Low Supply at Patrol Hut on [slope name][location] ";
    // document.getElementById('rende6').innerHTML temporary before database




    async function run() {
        try {
            // Connect the client to the server	(optional starting in v4.7)
            await client.connect();
            // Send a ping to confirm a successful connection
            await client.db("admin").command({ ping: 1 });
            console.log("Pinged your deployment. You successfully connected to MongoDB!");

            const db = client.db()

            const equipment = await db.collection("equipment")

            //POST route
            // await equipment.insertOne({ EquipmentName: "Bandages", Quantity: "0", Resupply: "Yes", Location: "Top of CliffHanger Chair Lift"})

            //UPDATE route
            // await equipment.updateOne({ _id: new mongoose.Types.ObjectId("66aba702d1e76943b093e073")}, {$set: {Quantity: "10"}})

            //DELETE route
            // await equipment.deleteOne({ _id: new mongoose.Types.ObjectId("66aea158e7f3340b7c051552") })

            //GET route
            const results = await db.collection("equipment").find().toArray()


            console.log("Get All Items to Resupply")
            console.log(results)
            window.results = results;
            console.log(window.results)
            document.getElementById('resultH2').innerHTML = results;





        } finally {
            // Ensures that the client will close when you finish/error
            await client.close();
        }
    }
    run().catch(console.dir);
    console.log("medical equipment for resupply")
}  









// app.get('/equipment', async (req, res) => {
//     try {
//         const equipment = await Equipment.find({});
//         res.status(200).json(equipment);


//     } catch (error) {
//         res.status(500).json({ message: error.message })
//     }
// })


// app.get('/equipment/:id', async (req, res) => {
//     try {
//         const { id } = req.params;
//         const equipment = await Equipment.findById(id);
//         res.status(200).json(equipment);
//     } catch (error) {
//         res.status(500).json({ message: error.message })
//     }
// })


// app.post('/equipment', async (req, res) => {
//     try {
//         const equipment = await Equipment.create(req.body)
//         res.status(200).json(equipment);

//     } catch (error) {
//         console.log(error.message);
//         res.status(500).json({ message: error.message })
//     }
// })

// // update a equipment
// app.put('/equipment/:id', async (req, res) => {
//     try {
//         const { id } = req.params;
//         const equipment = await Equipment.findByIdAndUpdate(id, req.body);
//         // we cannot find any equipment in database
//         if (!equipment) {
//             return res.status(404).json({ message: `cannot find any equipment with ID ${id}` })
//         }
//         const updatedEquipment = await Equipment.findById(id);
//         res.status(200).json(updatedEquipment);

//     } catch (error) {
//         res.status(500).json({ message: error.message })
//     }
// })

// // delete a equipment

// app.delete('/equipment/:id', async (req, res) => {
//     try {
//         const { id } = req.params;
//         const equipment = await Equipment.findByIdAndDelete(id);
//         if (!equipment) {
//             return res.status(404).json({ message: `cannot find any equipment with ID ${id}` })
//         }
//         res.status(200).json(equipment);

//     } catch (error) {
//         res.status(500).json({ message: error.message })
//     }
// })



// module.exports = app